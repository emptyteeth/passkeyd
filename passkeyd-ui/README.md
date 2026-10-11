# Passkeyd UIs

Front-ends for passkeyd, all built with [iced](https://iced.rs):

- **`passkeyd-ice-enroll`** — authorises creating a passkey.
- **`passkeyd-ice-select`** — picks a passkey and verifies the user.
- **`passkeyd-ice-selection`** — asks for the user's presence.
- **`passkeyd-ice-manager`** — the passkey manager's window.

Each is a short-lived, unprivileged process spawned by passkeyd through
`systemd-run` into the active user's session, talking to it over a private pipe.
`passkeyd-abi::framing` defines that protocol.

The appearance is controlled by `theme.conf`; set `PASSKEYD_THEME_PATH` to
override its location.
