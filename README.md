<div align="center">
  <img src="https://raw.githubusercontent.com/bjn7/passkeyd/main/icons/banner-passkeyd-2.png" alt="Alt text" width="512">
  <br><br>
  <strong>An Opinionated WebAuthn Authenticator</strong>
</div>

---

## About

Passkeyd is a Linux based WebAuthn authenticator that works with any WebAuthn supported application, including browsers. It supports both TPM and non-TPM devices.

## Security model

Two things are worth knowing before relying on this.

**User verification is enforced by passkeyd, not by the TPM.** The fingerprint,
password or PAM check happens in the daemon. Root can read the stored passkey
blobs and ask the TPM to sign without going through it. What the TPM protects
is the private key itself: it never leaves the chip and cannot be copied to
another machine. For everyone who is not root, user verification still has to
be passed.

**With `USE_TPM_CRYPTOGRAPHY=yes`, passkeys are bound to PCR 7** — the Secure
Boot policy (PK/KEK/db/dbx). A passkey only works while PCR 7 holds the value
it had when the passkey was created. Updating the Secure Boot key databases (a
`dbx` revocation update through fwupd or Windows Update, for example), changing
the platform key, or switching Secure Boot on or off changes PCR 7 and makes
existing passkeys unusable. The binding is stored inside the key and cannot be
changed afterwards, so such a passkey has to be deleted and registered again on
the website. Expect this roughly once or twice a year, the same way TPM-backed
LUKS unlock has to be re-enrolled after these updates.

Clearing the TPM, or resetting its owner hierarchy, also invalidates every
stored passkey, because they are wrapped by a key derived from that hierarchy.

## Installation

#### Install Binaries

<details>
<summary>Arch-based distro</summary>
<br>

The package is available in the [passkeyd](https://aur.archlinux.org/packages/passkeyd) <sup>AUR</sup>, which you can install using aur helper, For exmaple

```bash
# Using yay
yay -S passkeyd

# Using paru
paru -S passkeyd

# Using aura
aura -A passkeyd
```

</details>

<details>
<summary>Ubuntu-based distro</summary>
<br>

```bash
curl -fsSL https://github.com/bjn7/passkeyd/releases/latest/download/passkeyd.gpg | sudo tee /usr/share/keyrings/passkeyd.gpg >/dev/null
echo 'deb [signed-by=/usr/share/keyrings/passkeyd.gpg] https://github.com/bjn7/passkeyd/releases/latest/download ./' | sudo tee /etc/apt/sources.list.d/passkeyd.list
sudo apt-get update && sudo apt-get install passkeyd
```

</details>

#### Start the Passkeyd Service

<details>
<summary>Initialize Passkeyd</summary>
<br>

Before initializing the `passkeyd` service, you may want to configure it properly for your system, [Initial Required Configuration](https://github.com/bjn7/passkeyd/wiki/Initial-Required-Configuration).

```bash
sudo systemctl enable passkeyd
sudo systemctl start passkeyd
```

</details>

<details>
<summary> Testing the Passkey Authentication (optional)</summary>

<br>

To determine whether the passkey is working properly, you may follow this step.

1. Go to the [Webauthn Demo Site](https://webauthn.io)
2. Enter the any username and click Register.
3. You should see: "Success! Now try to authenticate..."
4. Click authenticate, A passphrase popup will appear, Enter your logged-in Linux user passphrase.

</details>

## Passkeyd UI Custom Theme

The configuration for the user interface can be found at `/usr/share/passkeyd/theme.conf`. If you need complete control over it, you can build your own front-end as well — see [`passkeyd-ui`](passkeyd-ui/README.md).

## Passkeyd Manager

To manage your passkeys, run `sudo passkeyd-manager`. It needs root because the
store is root-only, and it opens a window in the active user's session — the
list is read and deletions performed by the root side, which talks to the
window over a private pipe.

Click a site to see its passkeys, then **Delete** to remove either a single
passkey or the whole site. Each passkey shows its owner, since the store is
shared between users. A passkey marked *unowned* predates per-user ownership;
run `passkeyd-migrate` to assign it.

Deleting only removes it from this system, not from the website. You may still
need to remove it from the website separately.

### Contrubution

If you are willing to contribute, refer to [CONTRIBUTING.md](https://github.com/bjn7/passkeyd/blob/main/CONTRIBUTING.md)

### Alternatives

- ~~[libwebauthn](https://github.com/linux-credentials/libwebauthn)~~: TPM 2.0 support is marked as '**planned**' and appears to have been in that status since 2020.

- [tpm-fido](https://github.com/psanford/tpm-fido): Likely to work for a long time due to the longevity of TPM 2.0 and protocol considerations, but it was last updated 3 years ago, so it doesn’t appear to be actively maintained.

- [linux-id](https://github.com/matejsmycka/linux-id): A fork of [tpm-fido](https://github.com/psanford/tpm-fido) that is actively maintained.
