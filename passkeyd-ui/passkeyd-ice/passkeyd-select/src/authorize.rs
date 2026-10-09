use iced::widget::{column, container, text, text_input};
use iced::{Alignment, Element, Length, Padding};
use passkeyd_abi::utils::FallbackToPasswordReason;
use passkeyd_abi::{component::title_bar_component, theme};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct AuthorizationUI {
    pub password: String,
    /// Set once the daemon has rejected an answer, to show the helper text.
    pub is_invalid: bool,
    /// Why the daemon fell back to a password, so the prompt can say so.
    pub fallback_reason: Option<FallbackToPasswordReason>,
    /// Prompt text supplied by PAM, overriding the default description.
    pub prompt: Option<String>,
}

#[derive(Debug, Clone)]
pub enum UserResponse {
    Deny,
    Authorize, //=> pressed enter,
    ContentChanged(String),
}

impl AuthorizationUI {
    /// A prompt opened because fingerprint or PAM verification was not usable.
    pub fn fallback(reason: FallbackToPasswordReason) -> Self {
        Self {
            fallback_reason: Some(reason),
            ..Default::default()
        }
    }

    /// A prompt driven by a PAM conversation question.
    pub fn pam(prompt: String) -> Self {
        Self {
            prompt: Some(prompt),
            ..Default::default()
        }
    }

    pub fn view(&self) -> Element<'_, UserResponse, theme::StylisedTheme> {
        let title_bar = title_bar_component(
            passkeyd_locale::translate!("ui.select.authorize.title_bar"),
            UserResponse::Deny,
        );

        let description = if let Some(prompt) = &self.prompt {
            text(prompt.as_str())
        } else {
            match self.fallback_reason {
                Some(FallbackToPasswordReason::PamUnavailable) => text(
                    passkeyd_locale::translate!("ui.select.authorize.pam_unavailable"),
                ),
                Some(_) => text(passkeyd_locale::translate!(
                    "ui.select.authorize.fingerprint_unavailable"
                )),
                None => text(passkeyd_locale::translate!(
                    "ui.select.authorize.description"
                )),
            }
        }
        .class(theme::TextClass::SecondaryText)
        .size(16);

        let helper_text = text(passkeyd_locale::translate!(
            "ui.select.authorize.helper_text"
        ))
        .class(theme::TextClass::ErrorText);

        let password = container(column![
            text_input(
                &passkeyd_locale::translate!("ui.select.authorize.password"),
                &self.password
            )
            .on_submit(UserResponse::Authorize)
            .secure(true)
            .on_input(UserResponse::ContentChanged)
            .padding(Padding::new(12.0))
            .width(354),
            self.is_invalid.then_some(helper_text)
        ])
        .height(Length::Fixed(110.))
        .width(Length::Fill)
        .align_y(Alignment::Center)
        .align_x(Alignment::Center);

        let body = column![description, password].height(Length::Fill);

        column![title_bar, body]
            .spacing(16)
            .padding([26, 26])
            .height(Length::Fill)
            .into()
    }
}

/// The "touch the sensor" screen shown while a fingerprint is being verified.
#[derive(Debug, Clone, Default)]
pub struct FingerprintUI {
    /// Set when the daemon reports a failed match, to nudge the user to retry.
    pub retry: bool,
}

#[derive(Debug, Clone)]
pub enum FingerprintResponse {
    Deny,
}

impl FingerprintUI {
    pub fn view(&self) -> Element<'_, FingerprintResponse, theme::StylisedTheme> {
        let title_bar = title_bar_component(
            passkeyd_locale::translate!("ui.select.fingerprint.title_bar"),
            FingerprintResponse::Deny,
        );

        let description = text(passkeyd_locale::translate!(
            "ui.select.fingerprint.description"
        ))
        .class(theme::TextClass::SecondaryText)
        .size(16);

        let helper_text = text(passkeyd_locale::translate!(
            "ui.select.fingerprint.helper_text"
        ))
        .class(theme::TextClass::ErrorText);

        let body = column![description, self.retry.then_some(helper_text)]
            .spacing(16)
            .height(Length::Fill)
            .align_x(Alignment::Center);

        column![title_bar, body]
            .spacing(16)
            .padding([26, 26])
            .height(Length::Fill)
            .into()
    }
}
