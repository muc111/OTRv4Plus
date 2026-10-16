# One account, one device: sessions and your server

XMPP lets one account be signed in from several devices at once. Each
session is a separate *resource* (`alice@server/phone`,
`alice@server/laptop`). Anyone who has the password can add one. This page
covers what the app does about that and how to make the server allow only one.

## What someone with your password can and cannot do

| | Another session with your password |
|---|---|
| **OTRv4+ chats** | Gets ciphertext only. The keys live on your device, not on the server, so it cannot read past or present conversations. If it starts its own OTR session, your contacts see a **new, unverified fingerprint**: SMP fails, and the padlock is not shown as verified. |
| **Secure groups (MLS)** | Not a member. Gets ciphertext only. |
| **Plain rooms, presence, contact list, profile** | Sees them: these are not end-to-end encrypted. |
| **Your password** | Can change it, unless the server stops it. |

So a stolen password does not decrypt your messages. It does let someone act
as you on the server. Treat it as urgent.

## What the app does

- **Warning.** When the server reports another session of your account, the
  chat list (Android, desktop) shows *"Your account is also signed in on
  another device. If that isn't you, change your password now."* The
  terminal client prints the same warning, with the other session's full JID.
- **Sign out other devices.** If your account is a **server admin**, the
  warning has a *Sign out other devices* button. It sends the server's
  XEP-0133 `end-user-session` command with each other session's full JID,
  never the bare one, so your own session stays up. In the terminal:
  `/admin end-user-session`, then give the full JID.
- Signing a session out does not stop it signing in again. **Change the
  password** as well.

## Allowing only one session per account (Prosody)

This has to be enforced by the server; a client cannot stop another client
signing in. Use this repository's module
[`prosody/mod_otrv4plus_one_session.lua`](prosody/mod_otrv4plus_one_session.lua):
one session per account, and **the newest sign-in wins**. The older session
is signed out with the stream error `conflict`.

Why the newest wins: over I2P, a phone that drops its connection leaves its
old session on the server for minutes. When the first session won (the
community module `mod_c2s_limit_sessions`), reconnecting was refused by your
own dead session: *"This account is already signed in on another device"*
(T450, 2026-10-16). It also meant that anyone who signed in first with your
password locked **you** out. Now you always get back in, and they are the
one signed out.

Two devices cannot keep pushing each other out. The app, the desktop app
and the terminal client do **not** reconnect after being signed out this
way. They say: *"Signed out: this account signed in on another device…
If it wasn't you, change your password."* Pressing Connect signs in again,
which signs the other device out.

Install (the plugin folder must be in `plugin_paths`; it is on the T450):

```bash
sudo mkdir -p /usr/local/lib/prosody/custom_modules
sudo cp ~/OTRv4Plus/prosody/mod_otrv4plus_one_session.lua /usr/local/lib/prosody/custom_modules/
```

In `prosody.cfg.lua`, before any `VirtualHost`:

```lua
plugin_paths = { "/usr/local/lib/prosody/modules", "/usr/local/lib/prosody/custom_modules" }
max_resources = 1
```

Add `"otrv4plus_one_session";` to `modules_enabled`, and take out
`"c2s_limit_sessions";` if it is there; the two must not run together.
Then run `sudo prosodyctl check config && sudo systemctl restart prosody`.

`max_resources = 2` allows two devices, and a third signs the oldest out.
To run the stress test as the admin from another machine (`STRESS_TEST.md`),
you need that second slot, or the test signs your app out.

## If you see the warning and it is not you

1. Change the password: **Profile → Change password…** in the app or the
   desktop app (current password, then the new one twice). On the server
   itself: `sudo prosodyctl passwd alice@server`.
2. As an admin, press *Sign out other devices* (or, on the server,
   `prosodyctl shell` → `c2s:close("alice@server/resource")`).
3. Verify your contacts again (SMP). A session that is not yours has a
   different fingerprint, and verification shows it.
