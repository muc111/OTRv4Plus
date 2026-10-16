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
signing in. Prosody's community module
[`mod_c2s_limit_sessions`](https://modules.prosody.im/mod_c2s_limit_sessions)
limits how many resources one account may have connected. Its option is
`max_resources`, which defaults to 10.

On the server: `prosodyctl install` needs `luarocks`. Without it, the
module is a single file. Fetch it into a plugin folder:

```bash
sudo mkdir -p /usr/local/lib/prosody/custom_modules
cd /usr/local/lib/prosody/custom_modules
sudo wget -O mod_c2s_limit_sessions.lua \
  https://hg.prosody.im/prosody-modules/raw-file/tip/mod_c2s_limit_sessions/mod_c2s_limit_sessions.lua
```

In `prosody.cfg.lua`, before any `VirtualHost`:

```lua
plugin_paths = { "/usr/local/lib/prosody/modules", "/usr/local/lib/prosody/custom_modules" }
max_resources = 1
```

Add `"c2s_limit_sessions";` inside the existing `modules_enabled` list.
Then run `sudo prosodyctl check config && sudo systemctl restart prosody`.

**What it does** (read from the module's source): at resource bind it counts
the account's sessions. When there are already `max_resources`, it refuses
the **new** one with `policy-violation`, "Too many active connections to
this account". The session already signed in stays. The app, the desktop
app and the terminal client then say *"This account is already signed in on
another device"* instead of a generic connection error. The terminal stops;
the apps keep retrying.

Because the first session wins, if someone else signs in first, **you** are
locked out. Change the password on the server (`sudo prosodyctl passwd
alice@server`), then end their session (`sudo prosodyctl shell`, then
`c2s:close("alice@server")`).

**The trade-off over I2P.** When a phone loses its connection, the server can
keep the old session for several minutes before timing it out. With
`max_resources = 1`, the reconnect can be refused until then. The app keeps
retrying, so it gets back in, just later. `max_resources = 2` avoids that
delay and still blocks a third device, while the app's warning shows the
second. As an admin you also need a free slot to run the stress test (see
`STRESS_TEST.md`) from another machine.

## If you see the warning and it is not you

1. Change the password (Prosody: `sudo prosodyctl passwd alice@server`).
2. As an admin, press *Sign out other devices* (or, on the server,
   `prosodyctl shell` → `c2s:close("alice@server/resource")`).
3. Verify your contacts again (SMP). A session that is not yours has a
   different fingerprint, and verification shows it.
