//! The unprivileged half of the passkey manager.
//!
//! It runs in the active user's session and only knows how to draw: the list of
//! sites and passkeys, and a confirmation before deleting. Everything that
//! needs root — reading the store, deleting — happens on the other side of the
//! pipe, waited on by the root process that spawned this one.
//!
//! Never write to stdout except through `ipc`.

use std::process::ExitCode;

use iced::widget::{Space, button, column, container, row, scrollable, text};
use iced::window::Settings;
use iced::{Alignment, Element, Length, Padding, Task};

use passkeyd_abi::theme::{self, ButtonClass, TextClass};
use passkeyd_abi::utils::{ManagerEntry, ManagerReply, ManagerRequest, ManagerUI};

mod ipc;

/// What the app is currently asking the user to confirm, if anything.
#[derive(Debug, Clone)]
enum Confirm {
    Passkey {
        credential_id: Vec<u8>,
        label: String,
    },
    Site {
        rp_id: String,
        label: String,
    },
}

#[derive(Debug, Clone)]
pub enum Message {
    OpenSite(usize),
    Back,
    AskDeletePasskey { credential_id: Vec<u8>, label: String },
    AskDeleteSite { rp_id: String, label: String },
    ConfirmDelete,
    CancelDelete,
    Reply(ManagerReply),
    Closed,
    Close,
    /// The desktop switched between light and dark.
    SystemTheme(iced::theme::Mode),
}

/// A relying party with the passkeys stored under it.
struct Site {
    rp_id: String,
    name: String,
    passkeys: Vec<ManagerEntry>,
}

impl Site {
    /// The site's display name, falling back to its id.
    fn label(&self) -> &str {
        if self.name.is_empty() {
            &self.rp_id
        } else {
            &self.name
        }
    }
}

/// Groups the flat entries into sites, preserving the order they arrived in.
///
/// Deleting the last passkey of a site leaves its directory behind, so sites
/// with nothing in them are dropped rather than shown empty.
fn group(entries: Vec<ManagerEntry>) -> Vec<Site> {
    let mut sites: Vec<Site> = Vec::new();

    for entry in entries {
        match sites.iter_mut().find(|site| site.rp_id == entry.rp.id.as_str()) {
            Some(site) => site.passkeys.push(entry),
            None => sites.push(Site {
                rp_id: entry.rp.id.to_string(),
                name: entry
                    .rp
                    .name
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_default(),
                passkeys: vec![entry],
            }),
        }
    }

    sites.retain(|site| !site.passkeys.is_empty());
    sites
}

struct App {
    sites: Vec<Site>,
    /// `Some` while a site's passkeys are on screen.
    opened: Option<usize>,
    confirm: Option<Confirm>,
    /// Shown when the root side reports a failure.
    error: Option<String>,
}

impl App {
    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::OpenSite(index) => {
                self.opened = Some(index);
                Task::none()
            }
            Message::Back => {
                self.opened = None;
                Task::none()
            }

            Message::AskDeletePasskey { credential_id, label } => {
                self.confirm = Some(Confirm::Passkey { credential_id, label });
                Task::none()
            }
            Message::AskDeleteSite { rp_id, label } => {
                self.confirm = Some(Confirm::Site { rp_id, label });
                Task::none()
            }
            Message::CancelDelete => {
                self.confirm = None;
                Task::none()
            }
            Message::ConfirmDelete => {
                let Some(confirm) = self.confirm.take() else {
                    return Task::none();
                };

                let request = match confirm {
                    Confirm::Passkey { credential_id, .. } => {
                        ManagerRequest::DeletePasskey { credential_id }
                    }
                    Confirm::Site { rp_id, .. } => ManagerRequest::DeleteSite { rp_id },
                };

                // The root side answers with `Refreshed`, which redraws us.
                if ipc::send(&request).is_err() {
                    return iced::exit();
                }
                Task::none()
            }

            Message::Reply(reply) => {
                match reply {
                    ManagerReply::Refreshed(state) => {
                        self.sites = group(state.entries);
                        // The open site may have lost its last passkey.
                        if self.opened.is_some_and(|index| index >= self.sites.len()) {
                            self.opened = None;
                        }
                        self.error = None;
                    }
                    ManagerReply::Failed(reason) => self.error = Some(reason),
                }
                Task::none()
            }

            Message::SystemTheme(mode) => {
                theme::set_system_mode(mode);
                Task::none()
            }

            Message::Closed | Message::Close => iced::exit(),
        }
    }

    fn view(&self) -> Element<'_, Message, theme::StylisedTheme> {
        let title_bar = passkeyd_abi::component::title_bar_component(
            passkeyd_locale::translate!("manager.main.window_title"),
            Message::Close,
        );

        let body = match self.opened {
            None => self.site_list(),
            Some(index) => self.passkey_list(index),
        };

        let mut page = column![title_bar, body].spacing(16).padding([26, 26]);

        if let Some(confirm) = &self.confirm {
            page = page.push(self.confirmation(confirm));
        }
        if let Some(error) = &self.error {
            page = page.push(text(error.as_str()).class(TextClass::ErrorText));
        }

        page.height(Length::Fill).into()
    }

    fn site_list(&self) -> Element<'_, Message, theme::StylisedTheme> {
        if self.sites.is_empty() {
            return text(passkeyd_locale::translate!("manager.main.empty"))
                .class(TextClass::SecondaryText)
                .into();
        }

        let rows = self.sites.iter().enumerate().map(|(index, site)| {
            let label = format!("{}  ({})", site.label(), site.passkeys.len());
            row![
                button(text(label))
                    .class(ButtonClass::Component)
                    .width(Length::Fill)
                    .on_press(Message::OpenSite(index)),
                button(text(passkeyd_locale::translate!("manager.main.delete")))
                    .class(ButtonClass::Close)
                    .on_press(Message::AskDeleteSite {
                        rp_id: site.rp_id.clone(),
                        label: site.label().to_string(),
                    }),
            ]
            .spacing(8)
            .into()
        });

        scrollable(column(rows).spacing(4).width(Length::Fill))
            .height(Length::Fill)
            .into()
    }

    fn passkey_list(&self, index: usize) -> Element<'_, Message, theme::StylisedTheme> {
        let Some(site) = self.sites.get(index) else {
            return Space::new().into();
        };

        let header = row![
            button(text(passkeyd_locale::translate!("manager.main.back")))
                .class(ButtonClass::Component)
                .on_press(Message::Back),
            text(site.label()).size(16),
        ]
        .spacing(12)
        .align_y(Alignment::Center);

        let rows = site.passkeys.iter().map(|entry| {
            let account = entry
                .account
                .clone()
                .unwrap_or_else(|| passkeyd_locale::translate!("manager.main.no_account").into());
            // The store is shared, so say whose passkey this is. An unowned one
            // predates ownership and needs passkeyd-migrate.
            let owner: String = entry.owner.clone().unwrap_or_else(|| {
                passkeyd_locale::translate!("manager.main.unknown_owner", uid => entry.uid)
                    .into()
            });

            row![
                text(format!("{account}  [{owner}]"))
                    .class(TextClass::SecondaryText)
                    .width(Length::Fill),
                button(text(passkeyd_locale::translate!("manager.main.delete")))
                    .class(ButtonClass::Close)
                    .on_press(Message::AskDeletePasskey {
                        credential_id: entry.credential_id.clone(),
                        label: account.clone(),
                    }),
            ]
            .spacing(8)
            .align_y(Alignment::Center)
            .into()
        });

        column![
            header,
            scrollable(column(rows).spacing(4).width(Length::Fill)).height(Length::Fill),
        ]
        .spacing(12)
        .height(Length::Fill)
        .into()
    }

    /// The inline confirmation. The TUI used to open a second window for this.
    fn confirmation(&self, confirm: &Confirm) -> Element<'_, Message, theme::StylisedTheme> {
        let question = match confirm {
            Confirm::Passkey { label, .. } => {
                passkeyd_locale::translate!("manager.main.confirmation.passkey", what => label)
            }
            Confirm::Site { label, .. } => {
                passkeyd_locale::translate!("manager.main.confirmation.site", site => label)
            }
        };

        container(
            column![
                text(question).class(TextClass::PrimaryText).size(16),
                text(passkeyd_locale::translate!("manager.main.confirmation.note"))
                    .class(TextClass::SecondaryText)
                    .size(13),
                row![
                    button(text(passkeyd_locale::translate!(
                        "manager.main.confirmation.cancel"
                    )))
                    .class(ButtonClass::Component)
                    .on_press(Message::CancelDelete),
                    button(text(passkeyd_locale::translate!(
                        "manager.main.confirmation.confirm"
                    )))
                    .class(ButtonClass::Close)
                    .on_press(Message::ConfirmDelete),
                ]
                .spacing(8),
            ]
            .spacing(8)
            .padding(Padding::new(12.0)),
        )
        .width(Length::Fill)
        .into()
    }
}

fn main() -> ExitCode {
    passkeyd_locale::init_translations();

    let boot = || {
        let state: ManagerUI = match ipc::initial_state() {
            Ok(state) => state,
            Err(e) => {
                eprintln!("passkeyd-ice-manager: {e}");
                std::process::exit(1);
            }
        };

        let app = App {
            sites: group(state.entries),
            opened: None,
            confirm: None,
            error: None,
        };

        let listen = Task::run(ipc::replies(), |incoming| match incoming {
            ipc::Incoming::Reply(reply) => Message::Reply(reply),
            ipc::Incoming::Closed => Message::Closed,
        });

        (app, listen)
    };

    iced::application(boot, App::update, App::view)
        .window(Settings {
            maximized: false,
            minimizable: true,
            closeable: true,
            resizable: true,
            size: iced::Size {
                width: 560.0,
                height: 480.0,
            },
            ..Default::default()
        })
        .theme(|_app: &App| theme::current())
        .subscription(|_app: &App| {
            iced::system::theme_changes().map(Message::SystemTheme)
        })
        .run()
        .map(|()| ExitCode::SUCCESS)
        .unwrap_or(ExitCode::FAILURE)
}
