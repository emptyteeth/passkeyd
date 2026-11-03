use std::sync::mpsc::{self, TryRecvError};
use std::time::{Duration, Instant};

use anyhow::Context;
use ctap_types::ctap2::AuthenticatorDataFlags;
use ctap_types::ctap2::get_assertion::{AuthenticatorData, Request, Response, ResponseBuilder};
use ctap_types::{Bytes, webauthn::PublicKeyCredentialRpEntity};
use ctaphid_types::{Channel, DeviceError};
use log::{debug, error, info, warn};
use sha2::Digest;

use passkeyd_abi::config::{Auth, Config};
use passkeyd_abi::database::{get_passkeys, layout::Passkey};
use passkeyd_abi::framing::FrameReader;
use passkeyd_abi::session::{active_uid, username_from_uid};
use passkeyd_abi::utils::{
    FallbackToPasswordReason, PresenceUI, Readiness, SelectUI, ServiceMessage, SystemdChild, UI,
    UIMessage, spawn_ui,
};
use zbus::blocking::Connection;

use crate::auth::fprintd::{FprintDeviceProxyBlocking, FprintManagerProxyBlocking};
use crate::auth::pam::InteractiveConversation;
use crate::auth::pass::{PasswordCheck, check_password};
use crate::cryptography;
use crate::ctaphid::ctaphid::{Ctaphid, Keepalive};
use crate::ctaphid::{CtapStatus, TransportError};
use crate::utils::{cancellable_ui, has_another_fido_device};

pub fn get(
    hid: &mut Ctaphid,
    channel: Channel,
    config: &Config,
    req: Request,
) -> anyhow::Result<Response> {
    // The host has started its transaction timer. A keepalive now buys time
    // for the work below (loading passkeys, and the TPM sign at the end)
    // before the polling loops take over.
    let _ = hid.send_keepalive(channel);

    // Who is asking. Everything below is scoped to them: only their passkeys
    // are loaded, and only their credentials can authorize.
    let uid = active_uid().ok_or(CtapStatus::UvBlocked)?;

    let (rp_entity, mut passkeys) = load_passkeys(&req, uid)?;

    // A client may ask for an assertion with user presence explicitly turned
    // off. That is how Firefox probes for a passkey before running the real
    // ceremony (its conditional/autofill UI, and Chromium does the same): it
    // only wants to know whether the credential is here. A hardware key answers
    // such a request without a touch, so prompting here costs the user a
    // second, pointless verification for one login.
    //
    // Answer without a UI, and leave UP and UV clear in the authenticator data:
    // nothing was verified, and the relying party must be able to see that.
    let silent = req
        .options
        .as_ref()
        .is_some_and(|options| options.up == Some(false) && options.uv != Some(true));

    let (authorized_index, selected_by_user) = if silent {
        info!("GetAssertion: user presence not requested, answering without a prompt");
        if passkeys.is_empty() {
            anyhow::bail!(CtapStatus::NoCredentials);
        }
        // Any credential will do for a discovery probe; with an allow list this
        // is the only candidate.
        (0, false)
    } else {
        let action = authorization_action(has_another_fido_device(), config.no_pass, passkeys.len());
        info!(
            "GetAssertion: {} candidate passkey(s) for uid {}, action {:?}",
            passkeys.len(),
            uid,
            action
        );
        // The user picked from a list, unless there was no list to pick from.
        let selected_by_user = !matches!(action, AuthorizationAction::UseOnlyPasskey);
        let index = authorize(hid, channel, config, uid, &rp_entity, &passkeys, action)?;
        (index, selected_by_user)
    };

    let authorized_passkey = passkeys.swap_remove(authorized_index);

    let rp_id_hash = sha2::Sha256::digest(req.rp_id.as_bytes()).into();

    let flags = if silent {
        AuthenticatorDataFlags::empty()
    } else {
        AuthenticatorDataFlags::USER_VERIFIED | AuthenticatorDataFlags::USER_PRESENCE
    };

    let authenticator_data = AuthenticatorData {
        attested_credential_data: None,
        extensions: None,
        flags,
        rp_id_hash: &rp_id_hash,
        sign_count: authorized_passkey.sign_count + 1,
    };

    let auth_data_bytes = authenticator_data.serialize().unwrap();
    let mut signed_payload = auth_data_bytes.to_vec();
    signed_payload.extend_from_slice(req.client_data_hash);

    let mut crypto = cryptography::resolve_cryptography(config);
    let (_, sign) = crypto.sign_payload(
        authorized_passkey.credential_source.crypto_pair.clone(),
        &signed_payload,
    )?;

    let mut response = ResponseBuilder {
        auth_data: authenticator_data.serialize().expect("failed to serialize"),
        credential: ctap_types::webauthn::PublicKeyCredentialDescriptor {
            id: Bytes::from_slice(&authorized_passkey.credential_source.id).unwrap(),
            key_type: "public-key".into(),
        },
        signature: Bytes::from_slice(&sign).expect("Unexpected number of bytes"),
    }
    .build();

    // if let Some(opt) = req.options {
    //     if let Some(is_rk) = opt.rk
    //         && is_rk == true
    //     {
    //         response.user = Some(authorized_passkey.credential_source.other_ui.user);
    //      }
    // }

    // The user entity identifies the account. Without user verification, only
    // the user handle may be returned: name, display name and icon are
    // user-identifiable information the spec forbids in a silent response.
    let mut user = authorized_passkey
        .credential_source
        .other_ui
        .user
        .clone();
    if silent {
        user.name = None;
        user.display_name = None;
        user.icon = None;
    }
    response.user = Some(user);

    // `userSelected` says the credential was picked by the user on the
    // authenticator. It must not be present when the platform supplied an
    // allowList: there the credential is already determined.
    response.user_selected = match &req.allow_list {
        Some(_) => None,
        None if selected_by_user => Some(true),
        None => None,
    };

    authorized_passkey.sign_increment(rp_entity);

    Ok(response)
}

fn load_passkeys(
    req: &Request,
    uid: u32,
) -> anyhow::Result<(PublicKeyCredentialRpEntity, Vec<Passkey>)> {
    // Mock PublicKeyCredentialRpEntity, will be overriden by the
    // actual stored RP entity if one exists.
    let mut rp_entity = PublicKeyCredentialRpEntity {
        icon: None,
        id: req.rp_id.into(),
        name: None,
    };

    let mut passkeys = Vec::new();

    match &req.allow_list {
        Some(allow_cred) if !allow_cred.is_empty() => {
            for cred in allow_cred {
                if let Some((rp, passkey)) = Passkey::get(&rp_entity, cred.id, uid) {
                    rp_entity = rp;
                    passkeys.push(passkey)
                }
            }
        }

        Some(_) | None => {
            if let Some((rp, stored_passkeys)) = get_passkeys(&rp_entity, uid) {
                rp_entity = rp;
                passkeys.extend(stored_passkeys);
            }
        }
    }

    Ok((rp_entity, passkeys))
}

#[derive(Debug)]
enum AuthorizationAction {
    // Skip the authorization UI entirely, including password
    // and credential selection.
    NoCredentials,

    // Use the only available passkey directly, skips UI.
    UseOnlyPasskey,

    // Spawns presence UI to determine the user's intent,
    // either to use passkeyd or an external key. If the user's
    // intent is to use passkeyd, skip the UI and send the credentials directly.
    Presence,

    // Spawn the selection UI, which includes the auth prompt (if required) and
    // passkey selection (if multiple passkeys are available).
    Selection,
}

fn authorization_action(
    has_another_fido_dev: bool,
    no_pass: bool,
    passkey_count: usize,
) -> AuthorizationAction {
    // Dry run of match
    //
    // Situation                                                   Action
    // No other key + 0 passkeys	                            NoCredentials
    // No other key + no password + 1 passkey                   UseOnlyPasskey
    // Other key + 0 passkeys                                   Presence
    // Other key + no password + 1 passkey                      Presence
    // Anything else	                                        Selection

    match (has_another_fido_dev, no_pass, passkey_count) {
        // no other key and no credentials either,
        // send the no cerds directly. the password
        // does not matter here.
        (false, _, 0) => AuthorizationAction::NoCredentials,

        // no other key, no password
        // and but one credential
        // skip ui, send the cerds directly
        (false, true, 1) => AuthorizationAction::UseOnlyPasskey,

        // another key, but there is no either passkey
        // the user intent is probably to use
        // either security key or use passkeyd
        // so, presence to find user's intent.
        (true, _, 0) => AuthorizationAction::Presence,

        // another key, but there is one passkey
        // the user intent is probably to use
        // either security key or use passkeyd
        // so, presence to find user's intent.
        (true, true, 1) => AuthorizationAction::Presence,

        // If no another key, no password, there are more than 1 cerds, selection is obviously needed.
        // If another key, has password, any number of cerds, selection will handle it.
        _ => AuthorizationAction::Selection,
    }
}

fn authorize(
    hid: &mut Ctaphid,
    channel: Channel,
    config: &Config,
    uid: u32,
    rp_entity: &PublicKeyCredentialRpEntity,
    passkeys: &[Passkey],
    action: AuthorizationAction,
) -> anyhow::Result<usize> {
    match action {
        AuthorizationAction::NoCredentials => {
            anyhow::bail!(CtapStatus::NoCredentials);
        }

        AuthorizationAction::UseOnlyPasskey => {
            info!("Using the only available passkey without spawning UI.");
            Ok(0)
        }

        AuthorizationAction::Presence => authorize_presence(hid, channel, config, uid, passkeys),

        AuthorizationAction::Selection => {
            authorize_selection(hid, channel, config, uid, rp_entity, passkeys)
        }
    }
}

fn authorize_presence(
    hid: &mut Ctaphid,
    channel: Channel,
    config: &Config,
    uid: u32,
    passkeys: &[Passkey],
) -> anyhow::Result<usize> {
    let ui_data = PresenceUI {
        title: &passkeyd_locale::translate!("passkeyd.cerds.make.presence_ui.title"),
        description: &passkeyd_locale::translate!("passkeyd.cerds.make.presence_ui.description"),
        button: &passkeyd_locale::translate!("passkeyd.cerds.make.presence_ui.button"),
    };

    let approved = cancellable_ui(hid, channel, spawn_ui(config, UI::KeySelection, ui_data, uid))?
        .exit_status
        .success();

    if !approved {
        anyhow::bail!(CtapStatus::OperationDenied);
    }

    if passkeys.is_empty() {
        anyhow::bail!(CtapStatus::NoCredentials);
    }

    Ok(0)
}

fn authorize_selection(
    hid: &mut Ctaphid,
    channel: Channel,
    config: &Config,
    uid: u32,
    rp_entity: &PublicKeyCredentialRpEntity,
    passkeys: &[Passkey],
) -> anyhow::Result<usize> {
    // Passkeys vector should never be empty here. If it is, then it is a logical error.
    if passkeys.is_empty() {
        error!("Passkeys were unexpectedly empty, expected at least one passkey.");
        anyhow::bail!(CtapStatus::NoCredentials);
    }

    let ui_state = SelectUI {
        rp: rp_entity,
        other_uis: passkeys
            .iter()
            .map(|passkey| &passkey.credential_source.other_ui)
            .collect(),
        no_pass: config.no_pass,
        auth: config.auth,
    };

    authenticate_handler(hid, channel, config, uid, ui_state)
}

#[derive(Debug)]
enum AuthorizationOutcome {
    Authorized,
    UnAuthorized,
    FallbackToPassword(FallbackToPasswordReason),
}

/// How long the UI gets to shut itself down after a terminal service message
/// before the daemon kills its unit.
const UI_EXIT_GRACE: Duration = Duration::from_millis(500);

/// Wait for the UI to close, keeping the host informed while it does.
///
/// The browser is still waiting on this CTAP request during the grace period,
/// so it must hear from us here too.
fn wait_for_ui_exit(
    hid: &mut Ctaphid,
    channel: Channel,
    child: &mut SystemdChild,
    keepalive: &mut Keepalive,
) {
    let deadline = Instant::now() + UI_EXIT_GRACE;

    while Instant::now() < deadline {
        keepalive.tick(hid, channel);

        match child.inner.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

fn authenticate_handler(
    hid: &mut Ctaphid,
    channel: Channel,
    config: &Config,
    uid: u32,
    ui_state: SelectUI,
) -> anyhow::Result<usize> {
    let mut child = spawn_ui(config, UI::KeySelect, ui_state, uid);
    let mut reader = FrameReader::<UIMessage>::new();
    let mut keepalive = Keepalive::default();

    loop {
        if let Some(event) = try_ui_message(hid, channel, &mut child, &mut reader)? {
            match event {
                UIMessage::SelectionDoneMaybeStartAuth(i) => {
                    if !config.no_pass {
                        authorization(hid, channel, config, uid, &mut child, &mut reader)?;
                    } else {
                        // Nothing further is expected from the UI; let it close
                        // itself rather than killing it mid-render.
                        wait_for_ui_exit(hid, channel, &mut child, &mut keepalive);
                    }
                    return Ok(i);
                }
                _ => unreachable!(),
            }
        } else {
            keepalive.tick(hid, channel);
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// Returns Ok() for successfull authorization
fn authorization(
    hid: &mut Ctaphid,
    channel: Channel,
    config: &Config,
    uid: u32,
    child: &mut SystemdChild,
    reader: &mut FrameReader<UIMessage>,
) -> anyhow::Result<()> {
    let mut auth = &config.auth;
    let mut keepalive = Keepalive::default();

    loop {
        let auth_outcome = match auth {
            Auth::PASS => authorization_pass(hid, channel, uid, child, reader),
            Auth::FPRINT => authorization_fprint(hid, channel, uid, child, reader),
            Auth::PAM => authorization_pam(hid, channel, uid, child, reader),
        };

        // The UI owns the final "granted"/"denied" signal, so tell it how the
        // attempt ended before acting on the outcome ourselves. These sends are
        // best-effort: if the UI already closed itself the outcome still stands.
        match auth_outcome? {
            AuthorizationOutcome::Authorized => {
                let _ = child.send(&ServiceMessage::Authorized);
                // Give the UI a moment to tear itself down before `Drop` kills
                // the unit out from under it.
                wait_for_ui_exit(hid, channel, child, &mut keepalive);
                return Ok(());
            }
            AuthorizationOutcome::UnAuthorized => {
                let _ = child.send(&ServiceMessage::Denied);
                wait_for_ui_exit(hid, channel, child, &mut keepalive);
                anyhow::bail!(CtapStatus::UvBlocked);
            }
            AuthorizationOutcome::FallbackToPassword(reason) => {
                auth = &Auth::PASS;
                child.send(&ServiceMessage::FallbackToPassword(reason))?;
            }
        }
    }
}

/*
* Technically, I can check this initially before setting the config and fallback before ever reaching fprint, but the hardware could’ve just failed since the app session is gonna be long.
* idk, it just doesn’t feel right to check those initially when it could’ve clearly changed later over a long duration.
*/

/// Fall back to the password, recording why. These failures used to be
/// swallowed silently, which made a mis-declared D-Bus signature look like
/// "no fingerprint hardware".
fn fingerprint_fallback(context: &str, error: impl std::fmt::Display) -> AuthorizationOutcome {
    info!("[Fingerprint] {context}: {error}");
    AuthorizationOutcome::FallbackToPassword(FallbackToPasswordReason::FingerprintDeviceUnavailable)
}

fn authorization_fprint(
    hid: &mut Ctaphid,
    channel: Channel,
    uid: u32,
    child: &mut SystemdChild,
    _reader: &mut FrameReader<UIMessage>,
) -> anyhow::Result<AuthorizationOutcome> {
    let mut keepalive = Keepalive::default();

    let Ok(connection) = Connection::system() else {
        return Ok(fingerprint_fallback(
            "cannot reach the system bus",
            "connection failed",
        ));
    };
    let Ok(fprint_manager) = FprintManagerProxyBlocking::new(&connection) else {
        return Ok(fingerprint_fallback(
            "fprintd manager is unavailable",
            "is fprintd installed?",
        ));
    };

    let device_path = match fprint_manager.get_default_device() {
        Ok(path) => path,
        Err(error) => return Ok(fingerprint_fallback("no default fingerprint device", error)),
    };

    let Ok(fprint_device) = FprintDeviceProxyBlocking::new(&connection, &device_path) else {
        return Ok(fingerprint_fallback(
            "cannot open the fingerprint device",
            "device proxy failed",
        ));
    };

    let username = username_from_uid(uid).ok_or(CtapStatus::OperationDenied)?;
    let enrolled = match fprint_device.list_enrolled_fingers(&username) {
        Ok(enrolled) => enrolled,
        Err(error) => {
            return Ok(fingerprint_fallback(
                "cannot list enrolled fingerprints",
                error,
            ));
        }
    };

    if enrolled.is_empty() {
        info!("[Fingerprint] No enrolled fingerprint for {username}");
        return Ok(AuthorizationOutcome::FallbackToPassword(
            FallbackToPasswordReason::NoEnrolledFingerprints,
        ));
    }

    debug!("[Fingerprint] Claiming device...");
    if let Err(error) = fprint_device.claim(&username) {
        return Ok(fingerprint_fallback("cannot claim the device", error));
    }

    // The status signals arrive on their own thread; the loop below only ever
    // polls a channel.
    let (tx, rx) = mpsc::channel();
    let mut status_stream = fprint_device.receive_verify_status()?;
    std::thread::spawn(move || {
        while let Some(signal) = status_stream.next() {
            if let Ok(args) = signal.args() {
                if tx.send(args.result).is_err() {
                    break;
                }
            }
        }
    });

    const MAX_ATTEMPTS: usize = 3;
    let mut attempts = 0;

    // A failed read ends the verification session, so `verify-no-match` below
    // has to stop and restart it — otherwise fprintd is idle while this loop
    // waits for a signal that will never come, and the next touch does
    // nothing at all.
    if let Err(error) = fprint_device.verify_start("") {
        let _ = fprint_device.release();
        return Ok(fingerprint_fallback("cannot start verification", error));
    }

    loop {
        if let Ok(status) = rx.try_recv() {
            match status.as_str() {
                "verify-match" => {
                    let _ = fprint_device.verify_stop();
                    let _ = fprint_device.release();
                    debug!("[Fingerprint] Releasing device...");
                    return Ok(AuthorizationOutcome::Authorized);
                }

                "verify-no-match" => {
                    attempts += 1;

                    if attempts >= MAX_ATTEMPTS {
                        let _ = fprint_device.verify_stop();
                        let _ = fprint_device.release();
                        debug!("[Fingerprint] Releasing device...");
                        return Ok(AuthorizationOutcome::UnAuthorized);
                    }

                    // The session has to be stopped before a new one can
                    // start: fprintd reports the result but still holds the
                    // session open, so a bare `verify_start` comes back as
                    // AlreadyInUse. Without both calls the user is told to try
                    // again while the reader sits idle, and their next touch
                    // does nothing.
                    let _ = fprint_device.verify_stop();
                    if let Err(error) = fprint_device.verify_start("") {
                        let _ = fprint_device.release();
                        return Ok(fingerprint_fallback(
                            "cannot restart verification",
                            error,
                        ));
                    }
                    child.send(&ServiceMessage::Retry)?;
                }

                // The session is still running and the user just needs to
                // adjust: re-scan, centre the finger, swipe slower. Telling
                // them to retry is enough — restarting here would cancel the
                // scan they are already in the middle of.
                "verify-retry-scan"
                | "verify-swipe-too-short"
                | "verify-finger-not-centered"
                | "verify-remove-and-retry"
                | "verify-too-fast" => {
                    debug!("[Fingerprint] {status}");
                    child.send(&ServiceMessage::Retry)?;
                }

                // The device is gone for good; do not touch it again.
                "verify-disconnected" => {
                    info!("[Fingerprint] The reader was disconnected");
                    return Ok(AuthorizationOutcome::FallbackToPassword(
                        FallbackToPasswordReason::FingerprintDeviceUnavailable,
                    ));
                }

                other => {
                    warn!("[Fingerprint] Unexpected status '{other}', treating as an error");
                    let _ = fprint_device.verify_stop();
                    let _ = fprint_device.release();
                    return Ok(AuthorizationOutcome::FallbackToPassword(
                        FallbackToPasswordReason::FingerprintDeviceUnavailable,
                    ));
                }
            };
        };

        if child
            .inner
            .try_wait()
            .context("failed to poll UI process")?
            .is_some()
        {
            let _ = fprint_device.verify_stop();
            let _ = fprint_device.release();
            anyhow::bail!(CtapStatus::OperationDenied);
        }

        if try_recv_cancel(hid, channel)?.is_some() {
            let _ = fprint_device.verify_stop();
            let _ = fprint_device.release();
            // Dropping `child` kills the unit and reaps the process.
            anyhow::bail!(CtapStatus::KeepaliveCancel);
        };

        keepalive.tick(hid, channel);
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

fn authorization_pam(
    hid: &mut Ctaphid,
    channel: Channel,
    uid: u32,
    child: &mut SystemdChild,
    reader: &mut FrameReader<UIMessage>,
) -> anyhow::Result<AuthorizationOutcome> {
    let mut keepalive = Keepalive::default();

    let (question_tx, question_rx) = mpsc::channel();
    let (answer_tx, answer_rx) = mpsc::channel();
    let (pam_result_tx, pam_result_rx) = mpsc::channel();

    let conv = InteractiveConversation {
        answer_rx,
        question_tx,
        // Answer PAM's username prompt ourselves: the account is already known.
        username: username_from_uid(uid),
    };

    let Ok(mut client) = pam::Client::with_conversation("passkeyd", conv) else {
        return Ok(AuthorizationOutcome::FallbackToPassword(
            FallbackToPasswordReason::PamUnavailable,
        ));
    };

    std::thread::spawn(move || {
        let _ = pam_result_tx.send(client.authenticate());
    });

    loop {
        if let Ok(question) = question_rx.try_recv() {
            child.send(&ServiceMessage::PAMQuestion(question))?;
        }

        // The UI has a single answer channel regardless of auth mode, so a PAM
        // prompt is answered with the same `Password` message.
        if let Some(UIMessage::Password(ans)) = try_ui_message(hid, channel, child, reader)? {
            answer_tx
                .send(ans)
                .map_err(|_| anyhow::anyhow!("Unexpectedly, PAM authentication thread died"))?;
        }

        match pam_result_rx.try_recv() {
            Ok(Ok(())) => return Ok(AuthorizationOutcome::Authorized),
            Ok(Err(_pam_err)) => return Ok(AuthorizationOutcome::UnAuthorized),

            Err(TryRecvError::Disconnected) => {
                return Err(anyhow::anyhow!(
                    "Unexpectedly, PAM authentication thread died"
                ));
            }
            Err(TryRecvError::Empty) => (),
        }

        keepalive.tick(hid, channel);
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

fn authorization_pass(
    hid: &mut Ctaphid,
    channel: Channel,
    uid: u32,
    child: &mut SystemdChild,
    reader: &mut FrameReader<UIMessage>,
) -> anyhow::Result<AuthorizationOutcome> {
    let mut keepalive = Keepalive::default();

    let username = username_from_uid(uid).ok_or(CtapStatus::OperationDenied)?;

    loop {
        if let Some(UIMessage::Password(pass)) = try_ui_message(hid, channel, child, reader)? {
            match check_password(&username, &pass) {
                PasswordCheck::Verified => return Ok(AuthorizationOutcome::Authorized),

                // The lockout is enforced across requests, so a run of wrong
                // guesses ends the attempt here rather than letting the caller
                // start a fresh assertion with a fresh budget.
                PasswordCheck::LockedOut { retry_after } => {
                    info!(
                        "[Password] {username} is locked out for another {}s",
                        retry_after.as_secs()
                    );
                    return Ok(AuthorizationOutcome::UnAuthorized);
                }

                // Retrying cannot fix an expired or locked account, so stop
                // rather than let the user keep typing.
                PasswordCheck::Unusable(reason) => {
                    info!("[Password] refusing {username}: {reason}");
                    return Ok(AuthorizationOutcome::UnAuthorized);
                }

                PasswordCheck::Rejected => child.send(&ServiceMessage::Retry)?,
            }
        };
        keepalive.tick(hid, channel);
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// If `Some(())` is retuned, cancel request is received
/// None is returned, no cancel request
fn try_recv_cancel(hid: &mut Ctaphid, channel: Channel) -> anyhow::Result<Option<()>> {
    if !hid.hid.is_readable() {
        return Ok(None);
    }
    // get_webauthn is responsible for readable states
    // is_readble just read the status provided by get_webauthn
    // so, get_webauth must be called
    match hid.get_webauthn()? {
        Some((incoming_channel, _)) => {
            // Well, could handle this too by passing it to the dispatcher.
            // But I don't think it would be that useful. I mean, why the hell are you even invoking
            // auth twice(you need to invoke in one tab and then switch to another tab to invoke another)?
            // If you're exercising free will, that's a different case.
            // otherwise, GET YOUR SELF A BRAIN CHECK

            error!("sent busy to channel {incoming_channel:?} caz currently processing {channel}");

            anyhow::bail!(TransportError {
                channel: incoming_channel,
                err: DeviceError::ChannelBusy
            });
        }
        None if hid.is_cancelled(channel) => Ok(Some(())),
        _ => Ok(None),
    }
}

fn try_ui_message(
    hid: &mut Ctaphid,
    channel: Channel,
    child: &mut SystemdChild,
    reader: &mut FrameReader<UIMessage>,
) -> anyhow::Result<Option<UIMessage>> {
    if try_recv_cancel(hid, channel)?.is_some() {
        // Dropping `child` kills the unit and reaps the process.
        anyhow::bail!(CtapStatus::KeepaliveCancel);
    };

    // Drain the pipe before looking at the exit status: a UI that reports its
    // result and exits immediately still has a frame waiting to be read.
    if let Some(stdout) = child.inner.stdout.as_mut()
        && stdout.is_readable()
    {
        match reader.poll(stdout) {
            Ok(Some(message)) => return Ok(Some(message)),
            // The child closed its end; fall through to the exit check below.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
            Err(e) => return Err(e.into()),
            Ok(None) => {}
        }
    }

    if child
        .inner
        .try_wait()
        .context("failed to poll UI process")?
        .is_some()
    {
        anyhow::bail!(CtapStatus::OperationDenied);
    }

    Ok(None)
}

