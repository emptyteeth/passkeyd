use pam::Conversation;
use passkeyd_abi::utils::ConversationQuestion;
use std::ffi::{CStr, CString};
use std::sync::mpsc::{Receiver, Sender};

pub struct InteractiveConversation {
    pub question_tx: Sender<ConversationQuestion>,
    pub answer_rx: Receiver<String>,
    /// The account being authenticated.
    ///
    /// PAM's echo prompt is the username, and passkeyd always authenticates the
    /// one user that owns these passkeys, so it is answered directly rather
    /// than asked. That saves a step, and it also stops the user from naming a
    /// different account than the one whose passkeys are being used.
    ///
    /// This assumes the stack only uses an echo prompt for the login name,
    /// which is what `pam_unix` and the usual `system-auth` stacks do — and
    /// what the `pam` crate's own `PasswordConv` assumes too.
    ///
    /// `None` falls back to prompting, so a failed user lookup cannot wedge
    /// authentication.
    pub username: Option<String>,
}

impl Conversation for InteractiveConversation {
    fn info(&mut self, msg: &CStr) {
        let text = msg.to_string_lossy().into_owned();
        let _ = self.question_tx.send(ConversationQuestion::Info(text));
    }

    fn prompt_blind(&mut self, msg: &CStr) -> Result<CString, ()> {
        let text = msg.to_string_lossy().into_owned();
        self.question_tx
            .send(ConversationQuestion::SensitiveInput(text))
            .map_err(|_| ())?;
        let answer = self.answer_rx.recv().map_err(|_| ())?;

        CString::new(answer).map_err(|_| ())
    }

    fn prompt_echo(&mut self, msg: &CStr) -> Result<CString, ()> {
        if let Some(username) = &self.username {
            return CString::new(username.clone()).map_err(|_| ());
        }

        let text = msg.to_string_lossy().into_owned();
        self.question_tx
            .send(ConversationQuestion::Input(text))
            .map_err(|_| ())?;
        let answer = self.answer_rx.recv().map_err(|_| ())?;

        CString::new(answer).map_err(|_| ())
    }

    fn error(&mut self, msg: &CStr) {
        let text = msg.to_string_lossy().into_owned();
        let _ = self.question_tx.send(ConversationQuestion::Error(text));
    }
}
