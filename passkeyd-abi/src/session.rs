//! Works out which user is currently at the machine.
//!
//! A CTAP request arrives over a virtual HID device, and the WebAuthn payload
//! says nothing about who triggered it — a browser sends the same bytes
//! whoever is sitting in front of it. The only signal available is logind: the
//! active session on the physical seat.
//!
//! This is a heuristic, and worth being explicit about. If one user is at the
//! console while another has a browser running in the background, the console
//! user is the one that gets authenticated. That is the right answer for user
//! verification — someone has to be present at the machine — but the virtual
//! HID layer cannot attribute a request to a session by itself, so this is as
//! precise as the design allows.

use log::debug;
use zbus::blocking::Connection;
use zbus::proxy;
use zbus::zvariant::OwnedObjectPath;

/// Local sessions live on this seat. passkeyd already requires systemd.
const SEAT: &str = "seat0";

#[proxy(
    default_service = "org.freedesktop.login1",
    interface = "org.freedesktop.login1.Manager",
    default_path = "/org/freedesktop/login1"
)]
trait Manager {
    fn get_seat(&self, seat_id: &str) -> zbus::Result<OwnedObjectPath>;
}

#[proxy(
    default_service = "org.freedesktop.login1",
    interface = "org.freedesktop.login1.Seat"
)]
trait Seat {
    /// A `(session_id, object_path)` pair.
    #[zbus(property, name = "ActiveSession")]
    fn active_session(&self) -> zbus::Result<(String, OwnedObjectPath)>;
}

#[proxy(
    default_service = "org.freedesktop.login1",
    interface = "org.freedesktop.login1.Session"
)]
trait Session {
    #[zbus(property, name = "User")]
    fn user(&self) -> zbus::Result<(u32, OwnedObjectPath)>;

    #[zbus(property, name = "Class")]
    fn session_class(&self) -> zbus::Result<String>;

    #[zbus(property, name = "Remote")]
    fn remote(&self) -> zbus::Result<bool>;
}

/// The uid of the user currently at the machine.
///
/// `None` when nobody is: a locked or absent console, or a seat whose active
/// session is a greeter or a remote login.
pub fn active_uid() -> Option<u32> {
    let connection = Connection::system().ok()?;

    let seat = ManagerProxyBlocking::new(&connection)
        .ok()?
        .get_seat(SEAT)
        .ok()?;

    let (session_id, session_path) = SeatProxyBlocking::new(&connection, seat)
        .ok()?
        .active_session()
        .ok()?;

    let session = SessionProxyBlocking::new(&connection, session_path).ok()?;

    // A seat reports whatever is active on it, greeters included. Only a local
    // user session can stand behind a passkey.
    match session.session_class() {
        Ok(class) if class == "user" => {}
        Ok(class) => {
            debug!("ignoring session {session_id}: class is '{class}', not 'user'");
            return None;
        }
        Err(e) => {
            debug!("ignoring session {session_id}: cannot read its class: {e}");
            return None;
        }
    }

    match session.remote() {
        Ok(false) => {}
        Ok(true) => {
            debug!("ignoring session {session_id}: it is remote");
            return None;
        }
        Err(e) => {
            debug!("ignoring session {session_id}: cannot tell if it is remote: {e}");
            return None;
        }
    }

    let uid = session.user().ok().map(|(uid, _)| uid);
    debug!("active session {session_id} belongs to uid {uid:?}");
    uid
}

/// The login name for `uid`, if the account exists.
pub fn username_from_uid(uid: u32) -> Option<String> {
    let mut passwd = std::mem::MaybeUninit::uninit();
    let mut buffer = vec![0; std::mem::size_of::<libc::passwd>()];
    let mut result: *mut libc::passwd = std::ptr::null_mut();

    while unsafe {
        libc::getpwuid_r(
            uid,
            passwd.as_mut_ptr(),
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut result as _,
        )
    } == libc::ERANGE
    {
        buffer.resize(buffer.len() * 2, 0);
    }

    if result.is_null() {
        return None;
    }

    let passwd = unsafe { passwd.assume_init() };
    let name = unsafe { std::ffi::CStr::from_ptr(passwd.pw_name) };
    name.to_str().ok().map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Talks to the real logind, so it only means anything on a machine with an
    /// active local session. Ignored by default for that reason.
    #[test]
    #[ignore = "needs a live logind with an active local session"]
    fn resolves_the_active_console_user() {
        let uid = active_uid();
        println!("active uid: {uid:?}");
        assert!(uid.is_some(), "expected a local session to be active");
    }
}
