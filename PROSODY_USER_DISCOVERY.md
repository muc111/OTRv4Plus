# Prosody user discovery, the People list, and pending subscriptions

What the Android client can learn about other users on the Prosody server, how
it learns it, and what it does not claim. Written from the code
(`android_bridge/transport.py`, `android/.../chat/OnlineUsers.kt`) and the
relevant standards. The live server sits behind I2P and was **not** reachable
from the development environment, so nothing here was checked against its
configuration (see "Not validated").

## 1. A roster is not a directory

XMPP gives an ordinary account no standard way to list every user on a server
or every user who is online. The roster lists only the accounts this account
added or that added it. Presence arrives only for contacts with an approved
subscription.

The client therefore never:

* enumerates, guesses or brute-forces JIDs;
* probes accounts by sending presence or messages to names that nobody listed;
* invents "online" for anyone the server did not report.

## 2. The one server mechanism: XEP-0133

XEP-0133 (Service Administration) defines `get-online-users-list`
(`http://jabber.org/protocol/admin#get-online-users-list`). Prosody serves it
through `mod_admin_adhoc`, **to server admins only**.

`XmppTransport.discover_online_users()`:

1. sends one XEP-0030 `disco#items` to the account's own domain on the
   XEP-0050 commands node, which asks which ad-hoc commands the server offers
   this account;
2. runs the online-users command only if it is offered, submits the server's
   own form with `max_items` = `all` when the form offers that, and returns the
   JIDs in `onlineuserjids` (reduced to bare, case-folded, de-duplicated);
3. otherwise returns `mechanism: "none"` and no users.

Only our own server is ever addressed. The view model asks at most every
120 s while connected, plus when the user taps "Ask the server again".

**Consequence for an ordinary account on a default Prosody:** the answer is
`none`, and the People list shows contacts and requests only. The screen says
so in these words: "This server does not list its online users to this
account (XEP-0133 is admin-only on Prosody)…".

To get server-wide "Online — Add" rows, the server operator has to choose one
of these. None of them can be done from the client:

* make the account a Prosody admin (`admins = { … }`). This grants far more
  than a user list, so it is not recommended for ordinary users;
* give everyone a shared roster (`mod_groups` or the community module
  `mod_roster_allinall`), so that everyone is on everyone's roster and presence
  flows normally;
* run a user directory (XEP-0055 search, `mod_vjud`), which would need client
  support that does not exist yet.

## 2a. The OTRv4Plus Welcome room: primary discovery for ordinary accounts

**What it is.** A public, persistent MUC named exactly `OTRv4Plus Welcome`.
Its occupants are the people who are discoverable right now. It is a
discovery room and not a secure channel: its messages are ordinary MUC
traffic, readable by the server. Appearing in it grants nothing — no OTR
trust, no fingerprint, no SMP, no call and no file transfer.

**How the app finds it.** The room's JID is not written anywhere in the code.
The app looks it up after every successful sign-in (`android_bridge/welcome.py`,
`XmppTransport._welcome_flow`):

1. It sends disco#items to the account's own server and, for each item,
   disco#info. It keeps only services whose identity category is
   `conference`, meaning a MUC service.
2. It sends disco#items to each MUC service, which lists that service's
   **public** rooms.
3. It picks the room whose advertised name is **exactly** `OTRv4Plus Welcome`.
   If none matches, the state is `not_found`. If more than one matches, the
   state is `ambiguous`. In both cases nothing is joined.
4. It sends disco#info to that room to learn whether it is public, persistent
   and anonymous.
5. It joins the room under the account's localpart as nickname. If that
   nickname is taken, it retries once with a random suffix on **our own**
   nickname.

Nothing else is sent. The app queries no occupant, tries no JID, and
enumerates no user. Each sign-in builds a fresh transport, so a reconnect
repeats the whole lookup. When our stream drops, all occupant knowledge is
dropped with it.

**Where an address comes from.** An address comes only from the
`<item jid='…'/>` that the MUC **service** writes into an occupant's presence.
The service writes it, so an occupant cannot forge it. The room shows it to
ordinary occupants only when the room is **non-anonymous**
(`muc_nonanonymous`; in Prosody, `whois = "anyone"`).

In a **semi-anonymous** room, which is Prosody's default, only moderators see
real JIDs. Ordinary occupants see nicknames, and a nickname is not an address.
Those occupants are only counted. The People list says "N people in the
OTRv4Plus Welcome room have hidden addresses" and offers no Add button for
them.

**In the People list.** Revealed occupants merge by bare JID into the one list:

- someone not on the roster appears as **Online — Add**;
- a roster contact keeps its roster state: **Online — Added**,
  **Offline — Added**, **Pending**, or **Accept** for an incoming request.

Roster state always wins over what the room shows. Several resources or
nicknames of one account produce one row, and our own account never appears.
**Add** is the normal roster add plus `subscribe` (`add_contact`).

**Security.** Room presence is not contact presence. Before this change,
every occupant presence (`room@service/nick`) reached two places:

- the contact-presence handler, which made the room look like an online
  contact;
- the OTRv4Plus capability book, which then sent a disco#info **through the
  room** to each occupant.

Both paths are now closed (`XmppTransport._is_room_presence`). OTRv4Plus
capability is still learned only from a contact's own direct presence and
disco#info, per resource (`OTRV4PLUS_CAPABILITY.md`). Being in the Welcome
room never starts OTRv4+.

**What the server must provide (not verified on the live server).** The
live Prosody is reachable only over I2P and could not be inspected, so its MUC
service JID, whether the room exists, and its anonymity setting are all
**unknown** here. For discovery to work for ordinary accounts, the server
admin creates one room on the existing MUC component with these XEP-0045
configuration fields, from any XMPP client or with the room-config form:

| Field | Value |
|---|---|
| `muc#roomconfig_roomname` | `OTRv4Plus Welcome` (exact) |
| `muc#roomconfig_publicroom` | `1` (listed in disco#items) |
| `muc#roomconfig_persistentroom` | `1` |
| `muc#roomconfig_whois` | `anyone` (non-anonymous; needed for **Add**) |
| `muc#roomconfig_membersonly` | `0` |
| `muc#roomconfig_passwordprotectedroom` | `0` |

In Prosody, the MUC component must be loaded, for example
`Component "<service>" "muc"`. Prosody's `muc_room_default_public`,
`muc_room_default_persistent` and `muc_room_default_public_jids` options set
the same defaults for new rooms. Check them against the installed Prosody
version.

**Privacy cost.** In a non-anonymous room:

- every occupant sees every other occupant's **full JID, including the
  resource**, plus when they join and leave;
- auto-joining tells everyone in the room when you are online;
- if the room has an archive (`mod_muc_mam`), messages sent there are kept on
  the server.

The operator and the users should accept that trade knowingly. A
semi-anonymous room avoids it but gives no addresses, so only the counted
"hidden" note appears.

**Server-wide list (optional).** The XEP-0133 admin command (§2) is still
used where the account is allowed to run it. It adds to the Welcome room and
never replaces it.

## 3. The People list

There is one list: the old "Online users" section was removed. It has one row
per bare JID and never includes our own account.

| Row | Source | Action |
|---|---|---|
| Wants to add you | incoming `subscribe` while the policy is ASK | **Accept** (`answerSubscription(approve=true)`) |
| Online — Added | roster plus available presence, or a roster contact the server listed | none |
| Online | listed by the server (XEP-0133), not on the roster | **Add** (`addContact`, roster add plus `subscribe`) |
| Pending — waiting for them to accept | roster `ask="subscribe"` | none |
| Offline — Added | roster plus unavailable presence | none |
| Added — presence not shared | roster, subscription `from`/`none` | none |

Security facts are listed separately after the relation: "not encrypted" or
"OTR encrypted", then "SMP verified". Being online, being added, being able to
use OTRv4Plus (capability, `OTRV4PLUS_CAPABILITY.md`), being encrypted and
being verified are five different facts, and no row merges them.

Server-listed users are dropped the moment our own stream goes down or the
account changes. Resources are merged into one row, but the per-resource
capability used for OTRv4+ routing is kept separately in `otrv4plus_caps`.

## 4. Pending subscriptions: is there a two-day expiry?

No such timer exists in this client, and none has been added.

* RFC 6121 §3 defines no expiry for a pending outbound subscription request.
  The `ask="subscribe"` state stays until the contact approves or denies it,
  or until either side removes the roster item.
* Prosody stores pending requests with the roster and delivers an inbound
  request to the contact's next session. Core Prosody does not document or
  implement an expiry for them. A server could add one with a module, but the
  repository contains no Prosody configuration, and the live server's modules
  could not be inspected (see "Not validated").
* The client shows "Pending — waiting for them to accept" for as long as the
  server's roster says `ask="subscribe"`, and nothing else. If the server ever
  dropped the request, the roster push would clear the state and the row would
  become "Added — presence not shared". The client reflects the server; it does
  not guess a deadline.

If a two-day expiry is seen on the live server, it comes from that server's
configuration, and the operator should be asked which module sets it.

## Not validated

* The live Prosody's module list, admin list and any subscription-expiry
  module: the server is reachable only over I2P, which this environment
  cannot reach.
* XEP-0133 against the live server. The stanza shapes in
  `tests/test_android_online_users_discovery.py` are Prosody
  `mod_admin_adhoc`'s documented form and result, parsed by real slixmpp
  stanza classes. They are not a capture from this server.
