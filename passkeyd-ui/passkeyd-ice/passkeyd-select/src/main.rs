use std::{cell::RefCell, process::ExitCode, rc::Rc, sync::Mutex};

use iced::{
    Element, Subscription, Task,
    futures::{Stream, StreamExt, channel::mpsc},
    widget::operation::focus_next,
    window::Settings,
};
use zeroize::Zeroize;

use crate::{
    authorize::{AuthorizationUI, FingerprintResponse, FingerprintUI},
    select::SelectionUI,
};
use passkeyd_abi::{
    config::Auth,
    framing::{read_frame, write_frame},
    theme,
    utils::{ConversationQuestion, ServiceMessage, UIMessage},
};

mod authorize;
mod select;

/// Receiving end of the daemon -> UI pipe, handed to the iced subscription.
/// `Subscription::run` needs a `fn` pointer builder, so the receiver is parked
/// in a static for the builder to pick up.
static SERVICE_RX: Mutex<Option<mpsc::Receiver<ServiceMessage>>> = Mutex::new(None);

enum Flow {
    Selecting(Box<SelectionUI>),
    AwaitingFingerprint(FingerprintUI),
    Authorizing(AuthorizationUI),
}

#[derive(Debug, Clone)]
pub enum MessageBridge {
    Selection(select::UserResponse),
    Authorization(authorize::UserResponse),
    Fingerprint(authorize::FingerprintResponse),
    Service(ServiceMessage),
    /// The daemon hung up; there is nobody left to talk to.
    Disconnected,
}

struct StateMachine {
    flow: Flow,
    /// Set once the daemon has confirmed success. The daemon is the only
    /// authority on whether verification passed; the UI just reports it.
    authorized: Rc<RefCell<bool>>,
}

impl StateMachine {
    fn update(&mut self, message: MessageBridge) -> Task<MessageBridge> {
        match message {
            MessageBridge::Selection(response) => match response {
                select::UserResponse::Authorize(i) => {
                    // The daemon expects the chosen index before anything else.
                    if send(&UIMessage::SelectionDoneMaybeStartAuth(i)).is_err() {
                        return iced::exit();
                    }
                    match &self.flow {
                        // No verification to wait for, so the selection itself
                        // is the authorization.
                        Flow::Selecting(selection) if selection.no_pass => {
                            *self.authorized.borrow_mut() = true;
                            return iced::exit();
                        }
                        Flow::Selecting(selection) if selection.auth == Auth::FPRINT => {
                            self.flow = Flow::AwaitingFingerprint(FingerprintUI::default());
                        }
                        _ => self.flow = Flow::Authorizing(AuthorizationUI::default()),
                    }
                    focus_next()
                }
                select::UserResponse::Deny => iced::exit(),
            },

            MessageBridge::Authorization(response) => match response {
                authorize::UserResponse::Authorize => {
                    if let Flow::Authorizing(authorize) = &mut self.flow {
                        // The daemon decides whether this password is correct;
                        // it answers with `Retry`, `FallbackToPassword`,
                        // `Authorized` or `Denied`.
                        let mut pass = std::mem::take(&mut authorize.password);
                        let sent = send(&UIMessage::Password(pass.clone())).is_ok();
                        pass.zeroize();
                        if !sent {
                            return iced::exit();
                        }
                    }
                    Task::none()
                }
                authorize::UserResponse::ContentChanged(content) => {
                    if let Flow::Authorizing(authorize) = &mut self.flow {
                        authorize.password = content;
                    }
                    Task::none()
                }
                authorize::UserResponse::Deny => iced::exit(),
            },

            MessageBridge::Fingerprint(FingerprintResponse::Deny) => iced::exit(),

            MessageBridge::Service(message) => self.apply_service_message(message),

            MessageBridge::Disconnected => iced::exit(),
        }
    }

    fn apply_service_message(&mut self, message: ServiceMessage) -> Task<MessageBridge> {
        match message {
            ServiceMessage::Retry => {
                match &mut self.flow {
                    Flow::Authorizing(authorize) => authorize.is_invalid = true,
                    Flow::AwaitingFingerprint(fingerprint) => fingerprint.retry = true,
                    Flow::Selecting(_) => {}
                }
                Task::none()
            }
            ServiceMessage::FallbackToPassword(reason) => {
                self.flow = Flow::Authorizing(AuthorizationUI::fallback(reason));
                focus_next()
            }
            ServiceMessage::Authorized => {
                *self.authorized.borrow_mut() = true;
                iced::exit()
            }
            ServiceMessage::Denied => iced::exit(),
            ServiceMessage::PAMQuestion(question) => {
                let prompt = match question {
                    ConversationQuestion::Info(text)
                    | ConversationQuestion::Input(text)
                    | ConversationQuestion::SensitiveInput(text)
                    | ConversationQuestion::Error(text) => text,
                };
                // Keep anything already typed; only the prompt text changes.
                match &mut self.flow {
                    Flow::Authorizing(authorize) => authorize.prompt = Some(prompt),
                    _ => self.flow = Flow::Authorizing(AuthorizationUI::pam(prompt)),
                }
                focus_next()
            }
        }
    }

    fn view(&self) -> Element<'_, MessageBridge, theme::StylisedTheme> {
        match &self.flow {
            Flow::Selecting(ui) => ui.view().map(MessageBridge::Selection),
            Flow::AwaitingFingerprint(ui) => ui.view().map(MessageBridge::Fingerprint),
            Flow::Authorizing(ui) => ui.view().map(MessageBridge::Authorization),
        }
    }

    fn subscription(&self) -> Subscription<MessageBridge> {
        Subscription::run(service_stream)
    }
}

/// Reads frames off the daemon pipe on a dedicated thread. Blocking there is
/// fine; the iced executor only ever sees a ready-made channel.
fn spawn_daemon_reader() {
    let (sender, receiver) = mpsc::channel(16);
    *SERVICE_RX.lock().expect("service receiver poisoned") = Some(receiver);

    std::thread::spawn(move || {
        let mut sender = sender;
        let mut stdin = std::io::stdin().lock();
        // `Ok(None)` (daemon closed the pipe) and `Err` (protocol failure) both
        // mean there is nothing more to deliver.
        while let Ok(Some(message)) = read_frame::<_, ServiceMessage>(&mut stdin) {
            if sender.try_send(message).is_err() {
                break;
            }
        }
    });
}

fn service_stream() -> impl Stream<Item = MessageBridge> {
    let receiver = SERVICE_RX
        .lock()
        .expect("service receiver poisoned")
        .take();

    iced::futures::stream::unfold(receiver, |state| async move {
        let mut receiver = state?;
        match receiver.next().await {
            Some(message) => Some((MessageBridge::Service(message), Some(receiver))),
            None => Some((MessageBridge::Disconnected, None)),
        }
    })
}

fn send(message: &UIMessage) -> std::io::Result<()> {
    write_frame(&mut std::io::stdout().lock(), message)
}

pub fn main() -> ExitCode {
    passkeyd_locale::init_translations();

    let authorized = Rc::new(RefCell::new(false));
    let authorized_clone = Rc::clone(&authorized);

    let bootfn = move || {
        let selection_ui: SelectionUI = {
            let mut stdin = std::io::stdin().lock();
            read_frame(&mut stdin)
                .expect("Failed to read the initial state")
                .expect("The daemon closed the pipe before sending any state")
        };
        let needs_selection = selection_ui.other_uis.len() > 1;
        let skip_password = selection_ui.no_pass;

        // A single passkey needs no picker, so go straight to verification.
        let flow = if needs_selection {
            Flow::Selecting(Box::new(selection_ui))
        } else {
            match selection_ui.auth {
                Auth::FPRINT => Flow::AwaitingFingerprint(FingerprintUI::default()),
                _ => Flow::Authorizing(AuthorizationUI::default()),
            }
        };

        let state = StateMachine {
            authorized: Rc::clone(&authorized_clone),
            flow,
        };

        if !needs_selection {
            // With a single credential there is no picker, but the daemon still
            // blocks on the chosen index before it will start verifying, so
            // report it up front.
            if send(&UIMessage::SelectionDoneMaybeStartAuth(0)).is_err() {
                std::process::exit(1);
            }
            if skip_password {
                // No verification either: the daemon just needs the UI to close.
                *authorized_clone.borrow_mut() = true;
                std::process::exit(0);
            }
            spawn_daemon_reader();
            return (state, focus_next());
        }

        spawn_daemon_reader();
        (state, Task::none())
    };

    let _ = iced::application(bootfn, StateMachine::update, StateMachine::view)
        .subscription(StateMachine::subscription)
        .window(Settings {
            maximized: false,
            minimizable: false,
            closeable: false,
            resizable: false,
            size: iced::Size {
                width: 456.0,
                height: 293.0,
            },
            level: iced::window::Level::AlwaysOnTop,
            ..Default::default()
        })
        .decorations(false)
        .theme(|_state: &StateMachine| theme::StylisedTheme::default())
        .run();

    if *authorized.borrow() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
