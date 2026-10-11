//! Direct password verification against the shadow database.
//!
//! This is the fallback every other method degrades to, so it has to stand on
//! its own. It deliberately does not go through PAM — that keeps it working
//! when the PAM stack is missing or misconfigured, which is exactly when a
//! fallback matters. The cost is that PAM's protections do not apply here, so
//! the two that matter most are reimplemented locally:
//!
//! * a lockout after repeated failures, matching what `pam_faillock` would do
//! * the account-state checks `pam_unix`'s account phase performs

use std::collections::HashMap;
use std::ffi::{CStr, CString, c_char};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use log::{error, warn};

// libxcrypt is provided as a dependency.
// so, dynamic linking is fine
#[link(name = "crypt")]
unsafe extern "C" {
    fn crypt(key: *const c_char, salt: *const c_char) -> *mut c_char;
}

/// Mirrors the defaults Arch ships for `pam_faillock`, so choosing PASS does
/// not quietly become the weakest way into the account.
const MAX_FAILURES: u32 = 3;
const FAILURE_WINDOW: Duration = Duration::from_secs(900);
const LOCKOUT: Duration = Duration::from_secs(600);

/// How a password check ended.
#[derive(Debug)]
pub enum PasswordCheck {
    /// The password was correct.
    Verified,
    /// The password was wrong. Counts towards the lockout budget.
    Rejected,
    /// The account cannot authenticate at all — expired, locked, or without a
    /// usable password. Retrying will not help, so this does not consume the
    /// lockout budget.
    Unusable(&'static str),
    /// Too many recent failures. Refused without even checking the password.
    LockedOut { retry_after: Duration },
}

/// Recent failures per account.
///
/// Keyed by name rather than by process-global counter because the daemon
/// outlives any single request: without this, an attacker could simply start a
/// new assertion each time and get three fresh guesses, forever.
static ATTEMPTS: LazyLock<Mutex<HashMap<String, Attempts>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[derive(Default)]
struct Attempts {
    failures: u32,
    window_started: Option<Instant>,
    locked_until: Option<Instant>,
}

impl Attempts {
    /// How much longer this account stays locked, if it is.
    fn lockout_remaining(&self, now: Instant) -> Option<Duration> {
        match self.locked_until {
            Some(until) if until > now => Some(until - now),
            _ => None,
        }
    }

    /// True once the lockout has been served, so the record can be dropped.
    fn lockout_served(&self, now: Instant) -> bool {
        matches!(self.locked_until, Some(until) if until <= now)
    }

    /// Record a failure, returning true if this one triggered the lockout.
    fn record_failure(&mut self, now: Instant) -> bool {
        // Failures only accumulate while they are close together in time; a
        // guess today and a guess tomorrow are not a brute-force attempt.
        let within_window = matches!(
            self.window_started,
            Some(started) if now.duration_since(started) < FAILURE_WINDOW
        );
        if !within_window {
            self.window_started = Some(now);
            self.failures = 0;
        }

        self.failures += 1;

        if self.failures >= MAX_FAILURES {
            self.locked_until = Some(now + LOCKOUT);
            true
        } else {
            false
        }
    }
}

/// Check `password` for `username`.
pub fn check_password(username: &str, password: &str) -> PasswordCheck {
    if let Some(retry_after) = lockout_remaining(username) {
        return PasswordCheck::LockedOut { retry_after };
    }

    let Ok(username_c) = CString::new(username) else {
        return PasswordCheck::Unusable("username contains a NUL byte");
    };
    let Ok(password_c) = CString::new(password) else {
        return PasswordCheck::Unusable("password contains a NUL byte");
    };

    // Requires root, which the daemon has.
    let spwd = unsafe { libc::getspnam(username_c.as_ptr()) };
    if spwd.is_null() {
        return PasswordCheck::Unusable("no shadow entry");
    }
    let spwd = unsafe { &*spwd };

    let Ok(hash) = (unsafe { CStr::from_ptr(spwd.sp_pwdp) }).to_str() else {
        return PasswordCheck::Unusable("password hash is not valid UTF-8");
    };

    // shadow(5): an empty field means no password is set, and a leading '!' or
    // '*' means the account cannot log in at all. Neither can ever match.
    if hash.is_empty() || hash.starts_with('!') || hash.starts_with('*') {
        return PasswordCheck::Unusable("account has no usable password");
    }

    if let Some(reason) = account_problem(spwd) {
        return PasswordCheck::Unusable(reason);
    }

    let Ok(hash_c) = CString::new(hash) else {
        return PasswordCheck::Unusable("password hash contains a NUL byte");
    };

    // `crypt` writes to a static buffer, so this must not run concurrently.
    // The daemon handles one request at a time, and this is only called from
    // the main loop.
    let result = unsafe { crypt(password_c.as_ptr(), hash_c.as_ptr()) };
    if result.is_null() {
        error!("crypt() failed while checking {username}");
        return PasswordCheck::Unusable("crypt() failed");
    }
    let result = unsafe { CStr::from_ptr(result) };

    if constant_time_eq(result.to_bytes(), hash_c.to_bytes()) {
        record_success(username);
        PasswordCheck::Verified
    } else {
        record_failure(username);
        PasswordCheck::Rejected
    }
}

/// Whether the account is in a state where no password can succeed.
///
/// The numeric fields are passed separately so this stays testable.
fn account_problem(spwd: &libc::spwd) -> Option<&'static str> {
    let today = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(since_epoch) => (since_epoch.as_secs() / 86_400) as i64,
        Err(_) => return None,
    };

    account_problem_at(today, spwd.sp_lstchg, spwd.sp_max, spwd.sp_expire)
}

fn account_problem_at(today: i64, last_change: i64, max_age: i64, expires: i64) -> Option<&'static str> {
    // shadow(5): days since the epoch. -1 means "never".
    if expires >= 0 && today > expires {
        return Some("account has expired");
    }

    // A last-change day of 0 is how shadow marks "must change at next login".
    if last_change == 0 {
        return Some("password must be changed before it can be used");
    }

    if max_age >= 0 && last_change >= 0 && today > last_change + max_age {
        return Some("password has expired");
    }

    None
}

fn lockout_remaining(username: &str) -> Option<Duration> {
    let now = Instant::now();
    let mut attempts = ATTEMPTS.lock().unwrap_or_else(|e| e.into_inner());
    let entry = attempts.get(username)?;

    if let Some(remaining) = entry.lockout_remaining(now) {
        return Some(remaining);
    }

    // Lockout served; forget the record so the next attempt starts clean.
    if entry.lockout_served(now) {
        attempts.remove(username);
    }
    None
}

fn record_failure(username: &str) {
    let now = Instant::now();
    let mut attempts = ATTEMPTS.lock().unwrap_or_else(|e| e.into_inner());
    let entry = attempts.entry(username.to_owned()).or_default();

    if entry.record_failure(now) {
        warn!(
            "[Password] locking out {username} for {}s after {MAX_FAILURES} failed attempts",
            LOCKOUT.as_secs()
        );
    }
}

fn record_success(username: &str) {
    ATTEMPTS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(username);
}

/// Compare without leaking where the first difference is.
///
/// The length check is fine: the format of a crypt hash is not secret.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches_only_identical_slices() {
        assert!(constant_time_eq(b"$6$abc", b"$6$abc"));
        assert!(!constant_time_eq(b"$6$abc", b"$6$abd"));
        assert!(!constant_time_eq(b"$6$abc", b"$6$ab"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn lockout_triggers_on_the_third_failure() {
        let start = Instant::now();
        let mut attempts = Attempts::default();

        assert!(!attempts.record_failure(start));
        assert!(!attempts.record_failure(start + Duration::from_secs(1)));
        assert!(attempts.record_failure(start + Duration::from_secs(2)));

        assert_eq!(
            attempts.lockout_remaining(start + Duration::from_secs(3)),
            Some(LOCKOUT - Duration::from_secs(1))
        );
    }

    #[test]
    fn lockout_expires() {
        let start = Instant::now();
        let mut attempts = Attempts::default();
        let mut triggered_at = start;
        for i in 0..MAX_FAILURES {
            triggered_at = start + Duration::from_secs(i as u64);
            attempts.record_failure(triggered_at);
        }

        // The lockout is counted from the failure that triggered it.
        assert!(attempts.lockout_remaining(triggered_at + Duration::from_secs(1)).is_some());

        let after = triggered_at + LOCKOUT + Duration::from_secs(1);
        assert_eq!(attempts.lockout_remaining(after), None);
        assert!(attempts.lockout_served(after));
    }

    #[test]
    fn failures_outside_the_window_do_not_accumulate() {
        let start = Instant::now();
        let mut attempts = Attempts::default();

        for i in 0..MAX_FAILURES {
            let now = start + FAILURE_WINDOW * (i + 1);
            assert!(
                !attempts.record_failure(now),
                "failure {i} should have started a fresh window"
            );
        }
    }

    #[test]
    fn expired_account_is_unusable() {
        let today = 20_000;
        assert_eq!(
            account_problem_at(today, today - 1, -1, today - 1),
            Some("account has expired")
        );
    }

    #[test]
    fn expired_password_is_unusable() {
        let today = 20_000;
        assert_eq!(
            account_problem_at(today, today - 100, 90, -1),
            Some("password has expired")
        );
    }

    #[test]
    fn never_expiring_account_is_fine() {
        // What a default Arch account looks like: -1 across the board.
        assert_eq!(account_problem_at(20_000, 20_000 - 5, -1, -1), None);
    }

    #[test]
    fn password_marked_for_change_is_unusable() {
        assert_eq!(
            account_problem_at(20_000, 0, -1, -1),
            Some("password must be changed before it can be used")
        );
    }
}
