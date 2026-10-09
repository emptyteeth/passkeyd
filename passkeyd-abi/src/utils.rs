// use std::ops::{Deref, DerefMut};
use crate::{config::Config, database::layout::OtherUI};
use ctap_types::{
    serde::{cbor_serialize_to, ser::Writer},
    webauthn::PublicKeyCredentialRpEntity,
};
use log::debug;
use serde::Serialize;
use std::{
    os::fd::AsRawFd,
    process::{Child, ChildStdin, Command, Stdio},
};
use uuid::Uuid;

#[derive(Default)]
pub struct CborVec(pub Vec<u8>);

impl FromIterator<u8> for CborVec {
    fn from_iter<I: IntoIterator<Item = u8>>(iter: I) -> Self {
        Self(Vec::from_iter(iter))
    }
}

impl CborVec {
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }

    pub fn from_serializable<T>(obj: T, capacity_hint: usize) -> Self
    where
        T: Serialize,
    {
        let mut cbor_data = CborVec::with_capacity(capacity_hint);
        cbor_serialize_to(&obj, &mut cbor_data).expect("Failed to translate to cbor");
        cbor_data
    }
}

impl Writer for CborVec {
    type Error = ctap_types::serde::Error;
    fn write_all(&mut self, buf: &[u8]) -> ctap_types::serde::Result<(), Self::Error> {
        self.0.extend_from_slice(buf);
        Ok(())
    }
}

// impl Deref for CborVec {
//     type Target = Vec<u8>;
//     fn deref(&self) -> &Self::Target {
//         &self.0
//     }
// }

// impl DerefMut for CborVec {
//     fn deref_mut(&mut self) -> &mut Self::Target {
//         &mut self.0
//     }
// }

impl AsRef<[u8]> for CborVec {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

pub enum Cose {
    ES256([u8; 77]),
    RS256([u8; 273]),
}

pub fn encode_cose_es256(x: &[u8; 32], y: &[u8; 32]) -> Cose {
    let mut out = [0u8; 77];

    // Just wanna say, this bytes are crafted manually,
    // because, free will
    out[0] = 0xA5; //map with 5 elementss

    out[1] = 0x01; //key type (1)
    out[2] = 0x02; //ec2 (2)

    out[3] = 0x03; //ago 3
    out[4] = 0x26; // es256 -7

    out[5] = 0x20; //crv
    out[6] = 0x01; //256 1

    out[7] = 0x21; // x -2
    out[8] = 0x58; // byte string header
    out[9] = 0x20; //32 byte header
    out[10..10 + 32].copy_from_slice(x);

    out[42] = 0x22; // x -3
    out[43] = 0x58; // byte string header
    out[44] = 0x20; //32 byte header
    out[45..45 + 32].copy_from_slice(y);
    Cose::ES256(out)
}

pub fn encode_cose_rs256(n: &[u8; 256], e: &[u8; 3]) -> Cose {
    let mut out = [0u8; 273];
    out[0] = 0xA4; //map with 4 elementss

    out[1] = 0x01; //key type (3)
    out[2] = 0x03; //rsa (2)

    out[3] = 0x03; //ago 3
    out[4] = 0x39; // header for int, 2 byte argument
    out[5] = 0x01; // 256
    out[6] = 0x00; // -1-256 = -257

    out[7] = 0x20; // n -1
    out[8] = 0x59; // byte string, 2 byte length
    out[9] = 0x01; // len 256
    out[10] = 0x00;
    out[11..11 + 256].copy_from_slice(n);

    out[267] = 0x21; // e -2
    // out[268] = 0x58; // label 2
    out[268] = 0x43; // byte string, len 3
    out[269..269 + 3].copy_from_slice(e);
    Cose::RS256(out)
}

pub enum UI {
    KeyEnroll,
    KeySelect,
    KeySelection,
}

impl UI {
    #[allow(unused)]
    fn as_str_path(&self, config: &Config) -> String {
        #[cfg(debug_assertions)]
        {
            use std::{env, path::Path};
            let target_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../target/debug")
                .canonicalize()
                .unwrap()
                .to_string_lossy()
                .to_string();
            match self {
                UI::KeyEnroll => format!("{target_dir}/{}", "passkeyd-ice-enroll"),
                UI::KeySelect => format!("{target_dir}/{}", "passkeyd-ice-select"),
                UI::KeySelection => format!("{target_dir}/{}", "passkeyd-ice-selection"),
            }
        }

        #[cfg(not(debug_assertions))]
        {
            match self {
                UI::KeyEnroll => config.front_enroll.to_owned(),
                UI::KeySelect => config.front_select.to_owned(),
                UI::KeySelection => config.front_selection.to_owned(),
            }
        }
    }
}

pub struct SystemdChild {
    pub inner: Child,
    /// Kept alive for the whole UI session: the daemon pushes `ServiceMessage`s
    /// (retries, password fallbacks, PAM questions) through this pipe.
    pub stdin: ChildStdin,
    unit: String,
    uid: u32,
}

impl SystemdChild {
    pub fn send(&mut self, message: &ServiceMessage) -> anyhow::Result<()> {
        crate::framing::write_frame(&mut self.stdin, message).map_err(Into::into)
    }

    /// Wait for the UI to exit on its own, up to `timeout`.
    ///
    /// Used after a terminal `ServiceMessage` so the UI gets to shut down
    /// cleanly instead of being SIGKILLed by `Drop` mid-render.
    pub fn wait_for_exit(&mut self, timeout: std::time::Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            match self.inner.try_wait() {
                Ok(Some(_)) => return true,
                Ok(None) => std::thread::sleep(std::time::Duration::from_millis(10)),
                Err(_) => return false,
            }
        }
        false
    }

    pub fn kill(&mut self) -> std::io::Result<()> {
        // No need for killing inner, as
        // --wait is passed in systemd
        Command::new("systemctl")
            .arg(format!("--machine={}@", self.uid))
            .arg("--user")
            .arg("kill")
            .arg("-s")
            .arg("SIGKILL")
            .arg(&self.unit)
            .status()?;

        Ok(())
    }
}

impl Drop for SystemdChild {
    fn drop(&mut self) {
        // Every path that abandons the UI — cancel, error, early return — has to
        // tear the unit down, otherwise it lingers until the session ends.
        let _ = self.kill();
        // Reap only if the unit goes away promptly. `--wait` keeps systemd-run
        // alive for as long as the unit is, so blocking here would hang the
        // daemon whenever the kill did not take effect.
        let _ = self.wait_for_exit(std::time::Duration::from_millis(200));
    }
}

/// Non-blocking readiness check for a pipe. Used on both sides of the IPC to
/// decide whether a frame is waiting before attempting a read.
pub trait Readiness {
    fn is_readable(&self) -> bool;
}

impl<T: AsRawFd> Readiness for T {
    fn is_readable(&self) -> bool {
        let mut pollfd = libc::pollfd {
            fd: self.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ret = unsafe { libc::poll(&mut pollfd, 1, 0) };
        ret > 0 && (pollfd.revents & libc::POLLIN != 0)
    }
}

// Util function
pub fn spawn_ui<State>(config: &Config, ui: UI, state: State) -> SystemdChild
where
    State: Serialize,
{
    debug!("Spawning UI");
    let unit = format!("passkeyd-interface-{}", Uuid::new_v4());
    let mut child = std::process::Command::new("systemd-run")
        .arg(format!("--machine={}@", config.gui_uid))
        .arg("--user")
        .arg("--collect")
        .arg("--wait")
        .arg("--quiet")
        .arg("--unit")
        .arg(unit.clone())
        .arg("--pipe")
        .arg(ui.as_str_path(config))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn UI, are you root?");
    let mut stdin = child.stdin.take().expect("Failed to get stdin");
    crate::framing::write_frame(&mut stdin, &state).expect("Failed to write the initial UI state");

    SystemdChild {
        inner: child,
        stdin,
        uid: config.gui_uid,
        unit,
    }
}

#[derive(Serialize)]
pub struct PresenceUI<'a> {
    pub description: &'a str,
    pub title: &'a str,
    pub button: &'a str,
}

#[derive(Serialize)]
pub struct EnrollUI<'a> {
    pub rp: &'a PublicKeyCredentialRpEntity,
    pub other_ui: &'a OtherUI,
}

#[derive(Serialize)]
pub struct SelectUI<'a> {
    pub rp: &'a PublicKeyCredentialRpEntity,
    pub other_uis: Vec<&'a OtherUI>,
    pub no_pass: bool,
    /// Which verification screen the UI should present.
    pub auth: crate::config::Auth,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub enum UIMessage {
    SelectionDoneMaybeStartAuth(usize),
    /// The user's answer to a verification prompt. Used for both the password
    /// and PAM modes; the UI has one input field either way.
    ///
    /// The value is not zeroed on the wire — the pipe is private to the daemon
    /// and the under-privileged UI process.
    Password(String),
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub enum ServiceMessage {
    FallbackToPassword(FallbackToPasswordReason),
    PAMQuestion(ConversationQuestion),
    /// The last answer was rejected; keep the UI open for another attempt.
    Retry,
    /// Verification succeeded. The UI no longer has anything to wait for.
    Authorized,
    /// Verification failed for good. The UI should close and report denial.
    Denied,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub enum ConversationQuestion {
    Info(String),
    SensitiveInput(String),
    Input(String),
    Error(String),
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub enum FallbackToPasswordReason {
    FingerprintDeviceUnavailable,
    FingerprintUserUnavailable,
    NoEnrolledFingerprints,
    PamUnavailable,
}
