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

On the server (Prosody 0.12 or later):

```bash
sudo prosodyctl install --server=https://modules.prosody.im/rocks/ mod_c2s_limit_sessions
```

In `prosody.cfg.lua`, add it to `modules_enabled` and set the limit:

```lua
modules_enabled = {
    -- ...the modules already listed...
    "c2s_limit_sessions";
}
max_resources = 1
```

Then run `sudo prosodyctl reload` (or restart Prosody), and check with
`sudo prosodyctl shell` → `c2s:show()` while signing in from a second device.

**Check before relying on it.** We could not fetch the module's page while
writing this, so test how it behaves on your server. It either refuses the
new session or ends the old one. Sign in on the phone, then on the laptop, and
see which one stays connected.

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
