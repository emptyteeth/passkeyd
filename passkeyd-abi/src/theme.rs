use std::{env, fs, process::exit};

use iced::{
    Border, Color, Shadow, Vector,
    border::{self, Radius},
    theme::{self, Base},
    widget::{
        button, container,
        scrollable::{self, AutoScroll, Rail},
        svg, text, text_input,
    },
};
use serde::{Deserialize, Serialize};

/// One complete set of colours.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Palette {
    #[serde(with = "color_rgba")]
    pub background: Color,

    #[serde(with = "color_rgba")]
    pub primary_text: Color,

    #[serde(with = "color_rgba")]
    pub secondary_text: Color,

    #[serde(with = "color_rgba")]
    pub surface: Color,

    #[serde(with = "color_rgba")]
    pub surface_primary_text: Color,

    #[serde(with = "color_rgba")]
    pub surface_secondary_text: Color,

    #[serde(with = "color_rgba")]
    pub accent: Color,

    #[serde(with = "color_rgba")]
    pub scrollbar_track: Color,

    #[serde(with = "color_rgba")]
    pub scrollbar_thumb: Color,
}

/// Which palette to draw with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThemeMode {
    /// Follow the desktop's colour scheme.
    #[default]
    Auto,
    Light,
    Dark,
}

/// The desktop's colour scheme, shared process-wide.
///
/// iced delivers this through `system::theme_changes`, but the application's
/// `theme()` callback only receives the app state — and two of the front-ends
/// deserialize their state from CBOR, so there is nowhere to put a field
/// without changing the wire format. A process-global keeps the prompt's theme
/// reachable from `theme()` regardless of what the state looks like.
static SYSTEM_MODE: std::sync::atomic::AtomicU8 =
    std::sync::atomic::AtomicU8::new(ModeTag::Auto as u8);

#[repr(u8)]
enum ModeTag {
    Auto = 0,
    Light = 1,
    Dark = 2,
}

/// Record what the desktop reports. Called from the theme-change subscription.
pub fn set_system_mode(mode: theme::Mode) {
    let tag = match mode {
        theme::Mode::Light => ModeTag::Light,
        theme::Mode::Dark => ModeTag::Dark,
        theme::Mode::None => ModeTag::Auto,
    };
    SYSTEM_MODE.store(tag as u8, std::sync::atomic::Ordering::Relaxed);
}

/// The desktop's colour scheme as last reported.
pub fn system_mode() -> ThemeMode {
    match SYSTEM_MODE.load(std::sync::atomic::Ordering::Relaxed) {
        x if x == ModeTag::Light as u8 => ThemeMode::Light,
        x if x == ModeTag::Dark as u8 => ThemeMode::Dark,
        _ => ThemeMode::Auto,
    }
}

/// The theme to draw with, resolving the desktop's preference.
///
/// This is what every front-end's `theme()` callback should return.
pub fn current() -> StylisedTheme {
    StylisedTheme::shared().with_system(system_mode())
}

impl From<theme::Mode> for ThemeMode {
    fn from(mode: theme::Mode) -> Self {
        match mode {
            theme::Mode::Light => ThemeMode::Light,
            theme::Mode::Dark => ThemeMode::Dark,
            theme::Mode::None => ThemeMode::Auto,
        }
    }
}

/// The theme actually used for drawing.
///
/// Holds both palettes and picks between them, so a light/dark switch needs no
/// reload. `Deref` hands out the active one, which is why every widget catalog
/// below still just reads `self.accent` and friends.
#[derive(Debug, Clone)]
pub struct StylisedTheme {
    light: Palette,
    dark: Palette,
    /// The user's explicit choice, if any.
    preference: ThemeMode,
    /// What the desktop reports, used when `preference` is `Auto`.
    system: ThemeMode,
}

impl std::ops::Deref for StylisedTheme {
    type Target = Palette;

    fn deref(&self) -> &Palette {
        self.active()
    }
}

impl StylisedTheme {
    fn active(&self) -> &Palette {
        match self.preference {
            ThemeMode::Light => &self.light,
            ThemeMode::Dark => &self.dark,
            ThemeMode::Auto => match self.system {
                // `Auto` with no desktop preference: fall back to dark, which
                // is the palette passkeyd has always shipped.
                ThemeMode::Light => &self.light,
                _ => &self.dark,
            },
        }
    }
}

/// The colour used for failure text and the failed fingerprint mark.
///
/// Not part of the theme: it is fixed so a misconfigured theme cannot make
/// errors invisible.
///
/// The value is a light red rather than a deep one because the background is
/// dark. The obvious (180, 0, 0) only reaches 2.1:1 against it, below the 3:1
/// that non-text content should clear; this reaches 4.4:1.
pub const ERROR_TEXT_COLOR: Color = Color::from_rgb8(235, 90, 90);

/// The shape of `theme.conf`.
///
/// Three forms are accepted, so an existing single-palette file keeps working:
///
/// ```toml
/// # 1. flat: one palette, used whatever the desktop is set to
/// background = [36, 37, 50, 255]
/// ...
///
/// # 2. split, following the desktop
/// mode = "auto"
/// [light]
/// background = [...]
/// [dark]
/// background = [...]
///
/// # 3. one palette under an explicit mode
/// mode = "dark"
/// [dark]
/// background = [...]
/// ```
#[derive(Debug, Deserialize)]
struct ThemeFile {
    #[serde(default)]
    mode: ThemeMode,
    light: Option<Palette>,
    dark: Option<Palette>,
    #[serde(flatten)]
    flat: Option<Palette>,
}

impl ThemeFile {
    /// Resolve the three forms into the two palettes the theme draws from.
    fn into_palettes(self) -> (Palette, Palette, ThemeMode) {
        let mode = self.mode;

        match (self.flat, self.light, self.dark) {
            // A flat file is one palette for every mode. Pinning the preference
            // to `Auto` here would be wrong: `Auto` consults the desktop, and a
            // single-palette file should not change appearance with it.
            (Some(flat), None, None) => (flat.clone(), flat, mode),

            // Split (or partly split). A missing side falls back to the other,
            // so a file may define only the palette it cares about.
            (None, light, dark) => match (light, dark) {
                (Some(light), Some(dark)) => (light, dark, mode),
                (Some(light), None) => (light.clone(), light, mode),
                (None, Some(dark)) => (dark.clone(), dark, mode),
                // No colours at all; the built-in default is used.
                (None, None) => {
                    let default = builtin_palette();
                    (default.clone(), default, mode)
                }
            },

            // A flat section alongside a split one is ambiguous.
            (Some(_), light, dark) => {
                eprintln!(
                    "theme.conf mixes a flat palette with [light]/[dark]; ignoring the flat one"
                );
                let light = light.unwrap_or_else(builtin_palette);
                let dark = dark.unwrap_or_else(builtin_palette);
                (light, dark, mode)
            }
        }
    }
}

/// The colours passkeyd ships with, for when a theme file names none.
fn builtin_palette() -> Palette {
    Palette {
        background: Color::from_rgb8(36, 37, 50),
        primary_text: Color::from_rgb8(255, 255, 255),
        secondary_text: Color::from_rgb8(230, 230, 230),
        surface: Color::from_rgb8(45, 40, 60),
        surface_primary_text: Color::from_rgb8(236, 217, 217),
        surface_secondary_text: Color::from_rgb8(236, 217, 217),
        accent: Color::from_rgb8(160, 135, 255),
        scrollbar_track: Color::from_rgba8(115, 115, 115, 25.0 / 255.0),
        scrollbar_thumb: Color::from_rgba8(80, 80, 80, 90.0 / 255.0),
    }
}

impl Default for StylisedTheme {
    fn default() -> Self {
        Self::load(ThemeMode::Auto)
    }
}

impl StylisedTheme {
    /// The theme for this process, read from disk once.
    ///
    /// iced asks for the theme on every window synchronisation — that is, on
    /// every message — and reading and parsing the file each time was both
    /// wasteful and invisible. The file cannot change while a prompt is on
    /// screen anyway, so it is loaded once and only the mode is switched
    /// afterwards.
    pub fn shared() -> &'static StylisedTheme {
        static THEME: std::sync::OnceLock<StylisedTheme> = std::sync::OnceLock::new();
        THEME.get_or_init(|| Self::load(ThemeMode::Auto))
    }

    /// The same palettes, but resolving `Auto` against `system`.
    pub fn with_system(&self, system: ThemeMode) -> Self {
        Self {
            light: self.light.clone(),
            dark: self.dark.clone(),
            preference: self.preference,
            system,
        }
    }

    /// Load the theme file, using `system` when the file leaves the choice open.
    pub fn load(system: ThemeMode) -> Self {
        let path = env::var("PASSKEYD_THEME_PATH")
            .unwrap_or_else(|_| "/usr/share/passkeyd/theme.conf".to_string());

        let Ok(contents) = fs::read_to_string(path) else {
            let (light, dark) = (builtin_palette(), builtin_palette());
            return Self {
                light,
                dark,
                preference: ThemeMode::Auto,
                system,
            };
        };

        let file: ThemeFile = match toml::from_str(&contents) {
            Ok(file) => file,
            Err(error) => {
                eprintln!("theme.conf is not valid: {error}");
                exit(2);
            }
        };

        let (light, dark, preference) = file.into_palettes();
        Self {
            light,
            dark,
            preference,
            system,
        }
    }
}

impl Base for StylisedTheme {
    fn base(&self) -> theme::Style {
        theme::Style {
            background_color: self.background,
            text_color: self.primary_text,
        }
    }
    /// iced calls this with the desktop's colour scheme when the application
    /// does not pick a theme itself. That is the hook the whole auto mode hangs
    /// off, so the preference is translated and passed through rather than
    /// discarded.
    fn default(preference: theme::Mode) -> Self {
        Self::load(preference.into())
    }

    /// Report the tone actually in use, so iced can match its own widgets to it.
    fn mode(&self) -> theme::Mode {
        match self.active() as *const Palette {
            p if std::ptr::eq(p, &self.light) => theme::Mode::Light,
            _ => theme::Mode::Dark,
        }
    }
    fn palette(&self) -> Option<theme::Palette> {
        None
    }
    fn name(&self) -> &str {
        "Custom Theme"
    }
}

pub enum ButtonClass {
    Close,
    Approval,
    Component,
}

impl button::Catalog for StylisedTheme {
    type Class<'a> = ButtonClass;
    fn default<'a>() -> Self::Class<'a> {
        ButtonClass::Component
    }
    fn style(&self, class: &Self::Class<'_>, status: button::Status) -> button::Style {
        let (bg, text) = match status {
            button::Status::Active if matches!(class, ButtonClass::Close) => {
                (theme::palette::darken(self.accent, 0.06), self.accent)
            }
            button::Status::Active => (self.accent, self.primary_text),
            button::Status::Disabled => (
                theme::palette::lighten(self.accent, 0.3),
                theme::palette::lighten(self.accent, 0.3),
            ),
            button::Status::Hovered if matches!(class, ButtonClass::Close) => {
                (theme::palette::darken(self.accent, 0.12), self.accent)
            }
            button::Status::Hovered => (
                theme::palette::darken(self.accent, 0.3),
                theme::palette::darken(self.accent, 0.3),
            ),
            button::Status::Pressed => (
                theme::palette::darken(self.accent, 0.15),
                theme::palette::darken(self.accent, 0.06),
            ),
        };

        let (border_width, border_radius) = match class {
            ButtonClass::Approval => (0.0, 9.),
            ButtonClass::Close => (4., f32::MAX),
            ButtonClass::Component => (0.0, 0.0),
        };

        button::Style {
            background: if let ButtonClass::Component = class {
                None
            } else {
                // good first issue ig, use into instead
                Some(iced::Background::Color(bg))
            },
            text_color: text,
            border: iced::Border {
                color: theme::palette::lighten(self.accent, 0.1).scale_alpha(0.3),
                width: border_width,
                radius: Radius::new(border_radius),
            },
            ..Default::default()
        }
    }
}

pub enum TextClass {
    PrimaryText,                  // Title's text, approval button text
    SecondaryText,                // description's text
    ElevatedSurfacePrimaryText,   // Elevated surface text's site name
    ElevatedSurfaceSecondaryText, // Elevated surface text's site username
    ErrorText,                    // description's text
}

impl text::Catalog for StylisedTheme {
    type Class<'a> = TextClass;
    fn default<'a>() -> Self::Class<'a> {
        TextClass::PrimaryText
    }
    fn style(&self, item: &Self::Class<'_>) -> text::Style {
        let text_color = match item {
            TextClass::PrimaryText => self.primary_text,
            TextClass::SecondaryText => self.secondary_text,
            TextClass::ElevatedSurfacePrimaryText => self.surface_primary_text,
            TextClass::ElevatedSurfaceSecondaryText => self.surface_secondary_text,
            TextClass::ErrorText => ERROR_TEXT_COLOR,
        };

        text::Style {
            color: Some(text_color),
        }
    }
}

impl scrollable::Catalog for StylisedTheme {
    type Class<'a> = ();
    fn default<'a>() -> Self::Class<'a> {}
    fn style(&self, _class: &Self::Class<'_>, status: scrollable::Status) -> scrollable::Style {
        let container = container::Style::default();
        let scrollbar = Rail {
            background: Some(self.scrollbar_track.into()),
            border: border::rounded(1),
            scroller: scrollable::Scroller {
                background: match status {
                    scrollable::Status::Hovered {
                        is_horizontal_scrollbar_hovered: _,
                        is_vertical_scrollbar_hovered: _,
                        is_horizontal_scrollbar_disabled: _,
                        is_vertical_scrollbar_disabled: _,
                    } => theme::palette::lighten(self.scrollbar_thumb, 0.1).into(),
                    scrollable::Status::Dragged {
                        is_horizontal_scrollbar_dragged: _,
                        is_vertical_scrollbar_dragged: _,
                        is_horizontal_scrollbar_disabled: _,
                        is_vertical_scrollbar_disabled: _,
                    } => theme::palette::lighten(self.scrollbar_thumb, 0.05).into(),
                    scrollable::Status::Active {
                        is_horizontal_scrollbar_disabled: _,
                        is_vertical_scrollbar_disabled: _,
                    } => theme::palette::lighten(self.scrollbar_thumb, 0.05).into(),
                },
                border: Border {
                    radius: Radius::new(2),
                    width: 0.,
                    color: Color::TRANSPARENT,
                },
            },
        };

        let auto_scroll = AutoScroll {
            background: self.scrollbar_thumb.into(),
            border: border::rounded(4).width(1).color(self.scrollbar_thumb),
            shadow: Shadow {
                color: theme::palette::darken(self.scrollbar_thumb, 0.5),
                offset: Vector::ZERO,
                blur_radius: 0.,
            },
            icon: self.scrollbar_thumb,
        };

        scrollable::Style {
            container,
            vertical_rail: scrollbar,
            horizontal_rail: scrollbar,
            gap: None,
            auto_scroll,
        }
    }
}

impl text_input::Catalog for StylisedTheme {
    type Class<'a> = ();
    fn default<'a>() -> Self::Class<'a> {}
    fn style(&self, _class: &Self::Class<'_>, status: text_input::Status) -> text_input::Style {
        let (bg, text, border) = match status {
            text_input::Status::Active => (
                self.surface,
                self.primary_text,
                theme::palette::lighten(self.surface, 0.08).scale_alpha(0.75),
            ),
            text_input::Status::Disabled => (
                theme::palette::lighten(self.surface, 0.6),
                self.secondary_text,
                theme::palette::lighten(self.surface, 0.08).scale_alpha(0.75),
            ),
            text_input::Status::Focused { is_hovered: _ } => (
                self.surface,
                self.primary_text,
                theme::palette::lighten(self.surface, 0.08).scale_alpha(0.75),
            ),
            text_input::Status::Hovered => (
                theme::palette::darken(self.surface, 0.05).scale_alpha(0.9),
                self.primary_text,
                theme::palette::lighten(self.surface, 0.08).scale_alpha(0.75),
            ),
        };

        text_input::Style {
            background: bg.into(),
            border: Border {
                color: border,
                width: 2.,
                radius: Radius::new(4),
            },
            icon: self.surface_primary_text,
            placeholder: theme::palette::lighten(self.surface_primary_text, 0.4).scale_alpha(0.3),
            value: text,
            selection: theme::palette::lighten(self.accent, 0.2).scale_alpha(0.8),
        }
    }
}

pub enum ContainerClass {
    Elevated,
    UnElevated,
}
impl container::Catalog for StylisedTheme {
    type Class<'a> = ContainerClass;
    fn default<'a>() -> Self::Class<'a> {
        ContainerClass::UnElevated
    }
    fn style(&self, class: &Self::Class<'_>) -> container::Style {
        match class {
            ContainerClass::Elevated => container::Style {
                text_color: Some(self.surface_primary_text),
                background: Some(self.surface.into()),
                border: Border {
                    color: theme::palette::lighten(self.surface, 0.1).scale_alpha(0.8),
                    radius: Radius::new(6),
                    width: 1.,
                },
                shadow: Shadow {
                    color: theme::palette::lighten(self.surface, 0.1).scale_alpha(0.8),
                    offset: Vector::new(0., 0.),
                    blur_radius: 0.0,
                },
                ..Default::default()
            },
            ContainerClass::UnElevated => container::Style {
                text_color: None,
                background: None,
                border: Border {
                    color: theme::palette::lighten(self.surface, 0.4).scale_alpha(0.2),
                    radius: Radius::new(4),
                    width: 0.,
                },
                shadow: Shadow {
                    color: theme::palette::lighten(self.surface, 0.4).scale_alpha(0.3),
                    offset: Vector::new(0., 0.),
                    blur_radius: 0.,
                },
                ..Default::default()
            },
        }
    }
}

mod color_rgba {
    use iced::Color;
    use serde::{Deserialize, Deserializer, Serializer, de, ser::SerializeTuple};

    pub fn serialize<S>(color: &Color, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let rgba = color.into_rgba8();
        let mut seq = serializer.serialize_tuple(rgba.len())?;
        for c in rgba {
            seq.serialize_element(&c)?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Color, D::Error>
    where
        D: Deserializer<'de>,
    {
        let rgba_bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        if rgba_bytes.len() != 4 {
            return Err(de::Error::invalid_length(
                rgba_bytes.len(),
                &"a slice of length 4",
            ));
        }
        Ok(Color {
            r: rgba_bytes[0] as f32 / 255.0,
            g: rgba_bytes[1] as f32 / 255.0,
            b: rgba_bytes[2] as f32 / 255.0,
            a: rgba_bytes[3] as f32 / 255.0,
        })
    }
}

// impl Serialize for UserTheme {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: serde::Serializer,
//     {
//         // self.accent.into_rgba8()
//         let mut state = serializer.serialize_struct("UserTheme", 10)?;
//         state.serialize_field("background", &self.background.into_rgba8())?;
//         state.serialize_field("title", &self.background.into_rgba8())?;
//         state.serialize_field("sub_text", &self.background.into_rgba8())?;
//         state.serialize_field("surface", &self.background.into_rgba8())?;
//         state.serialize_field("surface_text", &self.background.into_rgba8())?;
//         state.serialize_field("surface_sub_text", &self.background.into_rgba8())?;

//         state.serialize_field("primary_text", &self.background.into_rgba8())?;
//         state.serialize_field("accent", &self.background.into_rgba8())?;
//         state.serialize_field("scrollbar_track", &self.background.into_rgba8())?;
//         state.serialize_field("scrollbar_thumb", &self.background.into_rgba8())?;

//         state.end()
//     }
// }

/// What a bundled symbol means, so the theme picks its colour — the same way
/// `TextClass` works. Carrying a semantic name rather than a `Color` is what
/// lets the widget be built without an instance of the theme.
#[derive(Debug, Clone, Copy)]
pub enum SymbolClass {
    /// The ordinary state: matches secondary text.
    Normal,
    /// Something failed and the user should try again.
    Error,
}

impl svg::Catalog for StylisedTheme {
    type Class<'a> = SymbolClass;
    fn default<'a>() -> Self::Class<'a> {
        SymbolClass::Normal
    }
    fn style(&self, class: &Self::Class<'_>, _status: svg::Status) -> svg::Style {
        svg::Style {
            color: Some(match class {
                SymbolClass::Normal => self.secondary_text,
                SymbolClass::Error => ERROR_TEXT_COLOR,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FLAT: &str = r#"
background = [1, 2, 3, 255]
primary_text = [4, 5, 6, 255]
secondary_text = [7, 8, 9, 255]
surface = [10, 11, 12, 255]
surface_primary_text = [13, 14, 15, 255]
surface_secondary_text = [16, 17, 18, 255]
accent = [19, 20, 21, 255]
scrollbar_track = [22, 23, 24, 25]
scrollbar_thumb = [26, 27, 28, 90]
"#;

    fn palettes(contents: &str) -> (Palette, Palette, ThemeMode) {
        toml::from_str::<ThemeFile>(contents)
            .expect("should parse")
            .into_palettes()
    }

    fn rgb(p: &Palette) -> [u8; 4] {
        p.background.into_rgba8()
    }

    /// An existing single-palette file must keep its exact look, and must not
    /// start changing with the desktop.
    #[test]
    fn a_flat_file_is_one_palette_for_every_mode() {
        let (light, dark, mode) = palettes(FLAT);

        assert_eq!(rgb(&light), [1, 2, 3, 255]);
        assert_eq!(rgb(&dark), [1, 2, 3, 255]);
        assert_eq!(mode, ThemeMode::Auto);

        // Crucially, `Auto` here must not consult the desktop: both palettes
        // are identical, so the appearance is fixed whatever the system says.
        let theme = StylisedTheme {
            light,
            dark,
            preference: mode,
            system: ThemeMode::Light,
        };
        assert_eq!(theme.active().background.into_rgba8(), [1, 2, 3, 255]);
    }

    /// A full dark palette with a different background, for the split tests.
    const DARK_SIDE: &str = r#"
background = [9, 9, 9, 255]
primary_text = [4, 5, 6, 255]
secondary_text = [7, 8, 9, 255]
surface = [10, 11, 12, 255]
surface_primary_text = [13, 14, 15, 255]
surface_secondary_text = [16, 17, 18, 255]
accent = [19, 20, 21, 255]
scrollbar_track = [22, 23, 24, 25]
scrollbar_thumb = [26, 27, 28, 90]
"#;

    #[test]
    fn a_split_file_switches_with_the_desktop() {
        let split = format!(
            "mode = \"auto\"\n[light]\n{}\n[dark]\n{}",
            FLAT.trim(),
            DARK_SIDE.trim()
        );
        let (light, dark, mode) = palettes(&split);

        assert_eq!(mode, ThemeMode::Auto);
        assert_eq!(rgb(&light), [1, 2, 3, 255]);
        assert_eq!(rgb(&dark), [9, 9, 9, 255]);

        let mut theme = StylisedTheme {
            light,
            dark,
            preference: mode,
            system: ThemeMode::Auto,
        };
        // No desktop preference falls back to dark.
        assert_eq!(theme.active().background.into_rgba8(), [9, 9, 9, 255]);

        theme.system = ThemeMode::Light;
        assert_eq!(theme.active().background.into_rgba8(), [1, 2, 3, 255]);

        theme.system = ThemeMode::Dark;
        assert_eq!(theme.active().background.into_rgba8(), [9, 9, 9, 255]);
    }

    /// Pinning a mode ignores the desktop entirely.
    #[test]
    fn an_explicit_mode_wins_over_the_desktop() {
        let split = format!(
            "mode = \"light\"\n[light]\n{}\n[dark]\n{}",
            FLAT.trim(),
            DARK_SIDE.trim()
        );
        let (light, dark, mode) = palettes(&split);
        assert_eq!(mode, ThemeMode::Light);

        let theme = StylisedTheme {
            light,
            dark,
            preference: mode,
            system: ThemeMode::Dark,
        };
        assert_eq!(theme.active().background.into_rgba8(), [1, 2, 3, 255]);
    }

    /// Defining only one section is allowed; it is used for both.
    #[test]
    fn a_half_split_file_reuses_the_side_it_has() {
        let only_dark = format!("[dark]\n{}\n", FLAT.trim());
        let (light, dark, _) = palettes(&only_dark);
        assert_eq!(rgb(&light), [1, 2, 3, 255]);
        assert_eq!(rgb(&dark), [1, 2, 3, 255]);
    }

    #[test]
    fn an_empty_file_falls_back_to_the_builtin_palette() {
        let (light, dark, _) = palettes("");
        let builtin = builtin_palette();
        assert_eq!(rgb(&light), builtin.background.into_rgba8());
        assert_eq!(rgb(&dark), builtin.background.into_rgba8());
    }

    /// The mode names in the file are the ones the docs promise.
    #[test]
    fn mode_names_parse() {
        for (text, expected) in [
            ("auto", ThemeMode::Auto),
            ("light", ThemeMode::Light),
            ("dark", ThemeMode::Dark),
        ] {
            let file = format!("mode = \"{text}\"\n{FLAT}");
            let (_, _, mode) = palettes(&file);
            assert_eq!(mode, expected, "mode = {text}");
        }
    }
}
