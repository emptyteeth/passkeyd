use std::borrow::Cow;

use crate::database::layout::OtherUI;
use ctap_types::webauthn::PublicKeyCredentialRpEntity;
use iced::{
    Alignment, Element, Font, Length,
    widget::{Button, button, column, container, image, row, text},
};

use super::theme;

pub fn user_component<'a, T>(
    rp: &'a PublicKeyCredentialRpEntity,
    other_ui: &'a OtherUI,
    on_click_signal: Option<T>,
) -> Button<'a, T, theme::StylisedTheme>
where
    T: 'static + Clone,
{
    let user_profile = if let Some(uicon) = &other_ui.user_icon {
        image(image::Handle::from_bytes(uicon.clone()))
    } else if let Some(sicon) = &other_ui.site_icon {
        image(image::Handle::from_bytes(sicon.clone()))
    } else {
        image(image::Handle::from_path(
            "/usr/share/icons/hicolor/64x64/apps/passkeyd.png",
        ))
    }
    .width(42)
    .height(42)
    .border_radius(f32::MAX);

    let site_title = if let Some(title) = &rp.name {
        text(title.as_str())
    } else {
        text(rp.id.as_str())
    }
    .size(16)
    .class(theme::TextClass::ElevatedSurfacePrimaryText);

    let user_display_name = other_ui
        .user
        .display_name
        .as_ref()
        .or(other_ui.user.name.as_ref())
        .map(|s| text(s.as_str()))
        .unwrap_or(text(
            String::from_utf8_lossy(other_ui.user.id.as_slice()).to_string(),
        ))
        .size(16)
        .class(theme::TextClass::ElevatedSurfaceSecondaryText);

    let user_info = container(column![site_title, user_display_name].padding([10, 0]))
        .align_y(Alignment::Center);
    button(
        container(
            row![user_profile, user_info]
                .spacing(16)
                .align_y(Alignment::Center)
                .padding([0, 16]),
        )
        .class(theme::ContainerClass::Elevated)
        .width(Length::Fixed(282.))
        .height(Length::Fixed(60.)),
    )
    .on_press_maybe(on_click_signal)
    // let selectable = button(container(row![row![user_profile].align_y(Alignment::Center), user_info].spacing(18)).align_x(Alignment::Center).align_y(Alignment::Center).class(theme::ContainerClass::Elevated)).width(Length::Fill).on_press_maybe(on_click_signal);
}

pub fn title_bar_component<'a, T>(
    title: Cow<'a, str>,
    close_signal: T,
) -> Element<'a, T, theme::StylisedTheme>
where
    T: Clone + 'static,
{
    let title_text = text(title)
        .size(20)
        .font(Font {
            weight: iced::font::Weight::ExtraBold,
            ..Default::default()
        })
        .width(Length::Fill);

    let close_button = button(
        text("🗙")
            .align_y(Alignment::Center)
            .align_x(Alignment::Center)
            .size(16)
            .line_height(1.)
            .height(Length::Fill)
            .width(Length::Fill),
    )
    .width(34)
    .height(34)
    .class(theme::ButtonClass::Close)
    .on_press(close_signal);

    row![title_text, close_button]
        .spacing(12)
        .align_y(Alignment::Center)
        .width(Length::Fill)
        .into()
}

/// A bundled SVG symbol, coloured by the theme according to `class`.
///
/// The fingerprint prompt is the only user of this for now: it needs a mark to
/// aim at, and for that mark to turn red when a read fails.
///
/// The markup is compiled in rather than read from disk. These are a few
/// hundred bytes, and a path that fails to resolve draws *nothing* — which
/// reads as a broken window rather than a missing asset, and would also have
/// needed a separate debug path since the file is not installed while
/// developing.
pub fn symbol_icon<'a, T: 'a>(
    name: Symbol,
    size: f32,
    class: theme::SymbolClass,
) -> iced::Element<'a, T, theme::StylisedTheme> {
    let markup = match name {
        Symbol::Fingerprint => include_str!("../../resources/icons/fingerprint.svg").as_bytes(),
    };

    iced::widget::svg(iced::widget::svg::Handle::from_memory(markup))
        .width(size)
        .height(size)
        .class(class)
        .into()
}

/// Every symbol compiled into the front-ends.
///
/// An enum rather than a string so that asking for a symbol that does not
/// exist is a compile error: this runs inside the prompt that gates
/// authentication, where a panic would strand the request.
pub enum Symbol {
    Fingerprint,
}
