//! The privileged half of the passkey manager.
//!
//! It owns the store — `/var/lib/passkeyd/database` is root-only, so it has to
//! run as root — but a root process cannot draw into a user's session. So this
//! side only reads the store and performs deletions, while the window is drawn
//! by `passkeyd-ice-manager` in the active user's session, spawned the same way
//! the passkey prompts are.
//!
//! Loop: wait for a request, act on it, send the new list back.

use std::process::ExitCode;

use ctap_types::webauthn::PublicKeyCredentialRpEntity;
use log::{error, info};

use passkeyd_abi::config::Config;
use passkeyd_abi::database::{
    all_relying_parties, get_all_passkeys, layout::LEGACY_UID, remove_passkey, remove_table,
    relying_party,
};
use passkeyd_abi::framing::FrameReader;
use passkeyd_abi::session::{active_uid, username_from_uid};
use passkeyd_abi::utils::{
    ManagerEntry, ManagerReply, ManagerRequest, ManagerUI, Readiness, SystemdChild, UI, spawn_ui,
};

fn main() -> ExitCode {
    passkeyd_locale::init_translations();

    if unsafe { libc::geteuid() } != 0 {
        eprintln!(
            "{}",
            passkeyd_locale::translate!("manager.main.root_access_required")
        );
        return ExitCode::from(126);
    }

    let config = match Config::initialize() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("passkeyd-manager: {e}");
            return ExitCode::FAILURE;
        }
    };

    // The window has to be drawn in someone's session; without one there is
    // nobody to show it to.
    let Some(uid) = active_uid() else {
        eprintln!("passkeyd-manager: no active local session to display the manager in");
        return ExitCode::FAILURE;
    };

    match run(&config, uid) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("passkeyd-manager: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(config: &Config, uid: u32) -> anyhow::Result<()> {
    let state = ManagerUI {
        entries: collect_entries(),
    };

    let mut child = spawn_ui(config, UI::KeyManager, state, uid);
    let mut reader = FrameReader::<ManagerRequest>::new();

    loop {
        // The pipe first: a request the GUI sent just before closing must still
        // be handled.
        if let Some(stdout) = child.inner.stdout.as_mut()
            && stdout.is_readable()
        {
            match reader.poll(stdout) {
                Ok(Some(request)) => {
                    if handle(request, &mut child)? {
                        continue;
                    }
                    break;
                }
                // The GUI closed its end; nothing more will arrive.
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e.into()),
                Ok(None) => {}
            }
        }

        if child.inner.try_wait()?.is_some() {
            break;
        }

        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // Dropping `child` kills the unit and reaps the process.
    info!("Manager closed");
    Ok(())
}

/// Act on one request. Returns `false` when the GUI asked to quit.
fn handle(request: ManagerRequest, child: &mut SystemdChild) -> anyhow::Result<bool> {
    match request {
        ManagerRequest::Quit => return Ok(false),

        ManagerRequest::DeletePasskey { credential_id } => {
            match find_site_of(&credential_id) {
                Some(rp) => {
                    info!("Removing a passkey for {}", rp.id);
                    remove_passkey(&rp, &credential_id);
                }
                None => {
                    child.send(&ManagerReply::Failed(
                        "That passkey is no longer in the store.".into(),
                    ))?;
                    return Ok(true);
                }
            }
        }

        ManagerRequest::DeleteSite { rp_id } => match relying_party(&rp_id) {
            Some(rp) => {
                info!("Removing every passkey for {rp_id}");
                remove_table(&rp);
            }
            None => {
                child.send(&ManagerReply::Failed(format!(
                    "No passkeys stored for {rp_id}."
                )))?;
                return Ok(true);
            }
        },
    }

    // Send the fresh list so the GUI redraws from the truth, not from what it
    // assumed the deletion would do.
    child.send(&ManagerReply::Refreshed(ManagerUI {
        entries: collect_entries(),
    }))?;
    Ok(true)
}

/// The site a credential id belongs to.
fn find_site_of(credential_id: &[u8]) -> Option<PublicKeyCredentialRpEntity> {
    for rp in all_relying_parties() {
        let Some((_, passkeys)) = get_all_passkeys(&rp) else {
            continue;
        };
        if passkeys
            .iter()
            .any(|passkey| passkey.credential_source.id == credential_id)
        {
            return Some(rp);
        }
    }
    None
}

/// Everything in the store, flat, with owners resolved.
///
/// The GUI runs unprivileged and cannot look up other accounts, so names are
/// resolved here and sent as text.
fn collect_entries() -> Vec<ManagerEntry> {
    let mut entries = Vec::new();

    for rp in all_relying_parties() {
        let Some((_, passkeys)) = get_all_passkeys(&rp) else {
            continue;
        };

        for passkey in passkeys {
            let user = &passkey.credential_source.other_ui.user;
            let account = user
                .display_name
                .as_ref()
                .map(ToString::to_string)
                .or_else(|| user.name.as_ref().map(ToString::to_string));

            entries.push(ManagerEntry {
                rp: rp.clone(),
                credential_id: passkey.credential_source.id.to_vec(),
                account,
                owner: match passkey.uid {
                    // Predates ownership; suggests running passkeyd-migrate.
                    LEGACY_UID => Some("unowned".into()),
                    uid => username_from_uid(uid),
                },
                uid: passkey.uid,
            });
        }
    }

    entries
}
