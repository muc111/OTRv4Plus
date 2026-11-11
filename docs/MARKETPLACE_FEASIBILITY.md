# Local shops in group chats — feasibility design

**Status: study only. Nothing here is built.** Written 2026-11-11 from the
owner's brief and from the repository as it stands (`dev`, rc.198). The legal
notes in §2 are general information, **not legal advice**; take that before
charging anyone money (§14).

---

## 0. Summary

**The brief (owner, 2026-11-11).** A group's creator can open a shop in the
group: items with weights, quantities and packs. A member picks items,
drops a GPS pin and opens an order for the creator to fulfil. Delivery costs
are set by radius and adjusted for busy times. The creator can add delivery
drivers; the buyer sees an estimated drop-off time and the driver confirms
it. **No payment goes through the app** (cash on delivery is between the two
people). The end goal: an open-source, independent marketplace built into the
group chats, covering local areas. A possible income stream: a paid monthly
tier.

**Verdict.**

| | |
|---|---|
| Technically | **Feasible**, mostly on what already exists: MLS groups with a creator role, offline location pins (`Location.kt`), photo metadata stripping, OTRv4+ 1:1 sessions. No new cryptography and no new dependency. Roughly 6 stages (§13). |
| Legally | **Feasible only with conditions** (§2). The same feature set, built with anonymous shops, is the shape of a drug-delivery service, and would be treated as one. |
| Commercially | Plausible as **hosting and support for identified local businesses**, not as rent from anonymous shops (§14). |

**The design rule that makes it work:** *the buyer is private, the shop is
identified.* Buyers get the app's full privacy (encrypted orders, a location
seen only by the shop and its driver, deleted after delivery). Shops are
businesses that the server they run on knows by name. That is the opposite of
a darknet market, and it is what lets a legitimate bakery, farm shop or
takeaway use it without the project becoming one.

---

## 1. What exists already

| Need | Already in the codebase |
|---|---|
| An encrypted group with an owner | MLS+ secure groups (`android_bridge/groups.py`, `client/otrv4plus_groups.py`); the creator invites, verifies and removes members |
| Messages only the creator can send | MLS authenticates every application message's sender; the creator's "group deleted" notice already relies on it (`groups.py`, `GROUP_DELETED_MARK`) |
| A private channel buyer → shop | OTRv4+ 1:1 sessions, SMP-verifiable, between any two members |
| A location, without a map service | `Location.kt`: GPS fix on the device, Plus Code + RFC 5870 `geo:` URI, no network; pins already go only into encrypted conversations |
| Photos without hidden data | the file pipeline strips EXIF/GPS and shows a metadata report before sending |
| Size limits on group messages | `MAX_ROOM_MESSAGE` = 1 MiB per MLS application message |
| Structured messages | prefixed bodies (`?OTRv4MLS1:`, `?OTRv4-MLS:`, call and file prefixes) and TLVs on the 1:1 path (`MESSAGE_META`, `TIP`) |

What does **not** exist: any notion of a shop, an item, an order or a
driver; any server-side registry; any distance or time maths.

---

## 2. Legal and abuse analysis (not legal advice)

### 2.1 "No payment in the app" is not the test

Whether a marketplace is lawful turns on **what is sold** and on **the
operator's role and knowledge**, not on who moves the money. Operators of
illegal markets have been convicted without ever touching a payment. Taking
payments out of the app removes payment-services regulation (no FCA/EMI
licence, no PSD2); it does not remove the rest.

### 2.2 Where the obligations come from

* **A paid tier makes the project a commercial marketplace operator.**
  * **EU — Digital Services Act.** An online platform that lets consumers
    conclude distance contracts with traders must collect and check the
    traders' identity (Art. 30, "traceability of traders") and design its
    interface for consumer information (Art. 31). Micro and small enterprises
    are exempt from these sections (Art. 19, 29) until they outgrow that
    status.
  * **UK — Online Safety Act 2023.** A user-to-user service has illegal-content
    duties: a risk assessment and proportionate systems. Consumer-protection
    law (DMCC Act 2024) applies to traders selling to consumers.
  * **Proceeds of crime.** Income knowingly derived from facilitating illegal
    sales is itself an offence in the UK (POCA 2002) and most countries.
* **Regulated goods** need the seller's licences whatever the platform:
  alcohol, tobacco and vapes, medicines, knives, food (food business
  registration). The platform must not make an unlicensed sale easy to hide.
* **Location data** is personal data (UK/EU GDPR). The design keeps it on
  devices and minimises it (§6), which is also what the law asks for.

### 2.3 The pattern problem

Each part of the brief is ordinary: Deliveroo has weights, pins and drivers.
Together, on an anonymity network, with anonymous shops, sales by weight and
"packs", cash drops, drivers, and a Monero courier already in the app, they
match a "dial-a-drug" delivery service. Police, app stores and journalists
read it that way. Consequences that would follow: removal from app stores,
the project's I2P server named in a case, and the maintainer's liability
judged on what the product obviously invites.

### 2.4 Conditions for building it

1. **Shops are identified to the server operator** (§10): a business name and
   contact, attested by the server. Members see "shop identified by
   <server>". No anonymous shops.
2. **No payment features and no link to the Monero courier.** Orders show a
   total and "pay on delivery as agreed". The shop never sees or sends an
   address, a payment request or a `/tip`.
3. **Shop terms are accepted at opening**, with a prohibited-goods list, and a
   **report** action exists for every member (§11).
4. **Categories come from a fixed list**; no free-form "packs" of unnamed
   goods. Units are standard (each, g/kg, ml/l, pack of N *of a named item*).
5. **No features whose only value is evading detection**: no self-destructing
   orders, no hidden shops, no drop-off "dead drops", no burner-driver
   accounts. (Ordinary retention limits for privacy are fine, §8.)
6. **The project does not run shops.** It ships software and, if paid, hosts
   servers for identified businesses (§14).

---

## 3. Scope

**In:** a shop per group (the creator's); a catalogue of items with variants;
a basket and an order sent privately to the shop; delivery quotes by
distance and time of day; drivers assigned by the creator; ETAs; an order
history on both sides; collection instead of delivery.

**Out (first version):** payments of any kind; reviews and ratings (abuse
magnet, needs moderation); search across shops or servers; shops outside a
group; stock synchronisation with outside systems; maps.

---

## 4. Data model

```
Shop        name, description, category set, opening hours, currency,
            minimum order, collection allowed (y/n), shop terms version,
            attestation (§10), catalogue version
Item        id, name, description, category (fixed list), photos (≤ 4,
            metadata stripped), unit (each | weight g/kg | volume ml/l |
            pack of N), variants [], in stock (y/n or count), hidden (y/n)
Variant     label ("250 g", "large"), quantity in unit, price
DeliveryPolicy  rings [(max km, base price)], max radius, per-km beyond
            first ring, busy-time multipliers [(days, from, to, ×)],
            slots per hour (capacity), collection point (optional pin)
Driver      member id (a group member), display name, vehicle class
            (foot | bike | car), active (y/n)
Order       id, buyer, shop, lines [(item, variant, count)], subtotal,
            delivery quote, total, delivery | collection, coarse area,
            exact pin (released on accept, §6), requested window,
            state (§9), driver, ETA, timestamps, signatures
```

Prices are integers in minor units (pence/cents) with a currency code. No
floating point in money.

---

## 5. Wire protocol

Two channels, chosen by who may read.

**The catalogue → the whole group (MLS).** A new application-message prefix,
`?OTRv4SHOP1:`, carrying a JSON catalogue (versioned, ≤ 512 KiB; photos go
as group file transfers referenced by hash). Accepted only if **MLS says the
sender is the group's creator** and its version is newer than the last one
held. Members keep the latest catalogue; a client that knows nothing of
shops shows "this group has a shop; update the app".

**Orders → the shop only (OTRv4+ 1:1).** A new TLV on the 1:1 session,
`SHOP_ORDER` (with the same kind of registration `MESSAGE_META` and `TIP`
use), carrying order messages: `request`, `quote`, `accept`, `assign`,
`eta`, `delivered`, `cancel`. Each carries the order id and a monotonic
sequence number; replays and out-of-order steps are refused. Only verified
(SMP) sessions may place orders. That reuses the app's strongest property,
and it means a shop knows each buyer is the same person as last time.

**Driver channel.** The shop forwards an accepted order to its driver over
the shop↔driver 1:1 session. The driver sends `eta` and `delivered` back to
the shop, which relays the ETA to the buyer. **The buyer and the driver
never need a direct channel**, so neither learns the other's account.

---

## 6. Location privacy

The most sensitive data in the feature, so it moves in steps.

1. **Quote.** The buyer's pin is reduced on the device to a **coarse area**
   (latitude and longitude rounded to 0.01°, about 1 km) and sent with the
   basket. That is enough to price the ring; it is not an address.
2. **Accept.** Only after the shop accepts does the buyer's app send the
   **exact pin** (with a short note: door, buzzer), to the shop only.
3. **Assign.** The shop forwards the exact pin to the one assigned driver.
4. **After.** Both ends delete the exact pin when the order is delivered,
   cancelled or 24 h old, whichever comes first. The order history keeps the
   coarse area only.
5. **Alternatives.** Collection from the shop, or a public meeting point the
   buyer picks, instead of a home.

Drivers' positions are never shown to buyers: the buyer sees "arriving about
18:40", not a dot on a map. No map tiles, no geocoding service, no outside
routing service at any step: everything is computed on the devices.

---

## 7. Delivery pricing and ETA

All on the device, from the shop's `DeliveryPolicy`:

```
distance  = haversine(shop or collection point, buyer area) × 1.3   (road factor)
ring      = first ring whose max km ≥ distance; refuse beyond max radius
price     = ring.base + per_km × max(0, distance − first ring)
price     = price × multiplier for the requested time (busy hours)
```

ETA uses the driver's vehicle class and the time of day (for example foot
5 km/h, bike 15 km/h, car 25 km/h, car at busy times 15 km/h) plus the shop's
preparation time. It is an estimate and is labelled as one. The driver
confirms or corrects it (`eta`), and the confirmed time is what the buyer
sees. Busy-time multipliers and speeds are the shop's settings, with these
defaults. A capacity per hour lets the shop stop accepting orders for a full
slot instead of over-promising.

---

## 8. Order lifecycle and storage

```
requested ──quote──▶ quoted ──accept (buyer)──▶ accepted ──assign──▶ out for delivery ──delivered──▶ done
    │                   │                          │                        │
    └──── cancel ───────┴──────── cancel ──────────┴──────── cancel ────────┘
```

* The shop may decline (`cancel` with a reason); the buyer may cancel until
  the order is out for delivery.
* An order expires if no step happens for 2 hours.
* **Storage:** orders live in the app's encrypted vault (the app lock's layer
  over the Keystore, desktop's sealed files). Buyer side: 90 days of history,
  coarse area only. Shop side: the shop's choice, default 90 days, because a
  real business needs records (tax, food safety).
* **Wipe and Exit** removes shop data with everything else.

---

## 9. Drivers

* A driver is a group member the creator marks as a driver; the creator can
  remove the mark at any time.
* A driver sees **only orders assigned to them**, with the exact pin,
  the lines to deliver, the buyer's chosen display name and the note.
* A driver sets **on duty / off duty**; the shop assigns among on-duty
  drivers (by hand at first; nearest-by-estimate later).
* A driver's own position never leaves their phone; only `eta` values do.

---

## 10. Shop identity (attestation)

A shop is opened only with an **attestation from the server it runs on**:

1. The creator fills in the business name, a contact (phone or email) and
   accepts the shop terms.
2. The server operator checks it however they choose (for a hosted business
   tier: at sign-up, with the payment) and signs
   `(server, creator's identity fingerprint, business name, expiry)` with the
   server's attestation key.
3. The app shows "shop identified by <server>" and refuses to open a shop
   catalogue without a valid, unexpired attestation for the creator's key.

**Feasibility.** The signing key's public half is published by the server
(service discovery) and, for the project's own server, shipped in the app
like its I2P address. The signing is a small admin tool; no Prosody module is
needed in the first version (the attestation travels with the catalogue).
The operator learns the business identity, never the buyers or the orders.

---

## 11. Abuse controls

* **Report.** Every member can report a shop or a listing to the server
  operator: the listing's text and photos plus the shop's attestation, sent
  by the reporter's choice. The operator can revoke the attestation; the
  shop then stops opening in every member's app.
* **Shop terms and prohibited goods** shown before opening and linked from
  the shop.
* **Fixed categories** and standard units (§2.4).
* **Rate limits** on orders per buyer per shop (no order floods).
* **Group creator controls**: a shop can be closed, and members removed,
  from the existing group screens.

These cannot make illegal trade impossible (no platform can); they make the
product unsuited to it and give operators the means to act.

---

## 12. Threat model (what could go wrong technically)

| Threat | Defence |
|---|---|
| A member posts a fake catalogue | Accepted only when MLS authenticates the creator as sender; version must increase |
| Prices changed in transit | MLS / OTRv4+ authenticate every byte; the quote is signed into the order |
| A forged order or a forged acceptance | Orders only on SMP-verified 1:1 sessions; sequence numbers refuse replays |
| Exact address leaked | Sent only after accept, only to shop and assigned driver, deleted within 24 h (§6) |
| Driver tracked by buyers | Drivers' positions never leave their phone; buyers see ETAs only |
| Malicious images in listings | The existing file viewer (hidden-data scan, metadata tabs) handles them |
| Order spam / denial of service | Per-buyer rate limits; orders only from members; capacity per slot |
| A rogue shop | Report → attestation revoked → shop closed for everyone |
| Server operator snooping | The operator sees encrypted traffic and the attestation only; never orders, items bought or locations |

---

## 13. Effort and stages

| Stage | What | Rough size |
|---|---|---|
| 1 | Protocol and core in Python (`client/otrv4plus_shop.py`): catalogue, orders, state machine, pricing, ETA maths; Rust untouched; full tests | 1–2 weeks |
| 2 | Attestation: admin tool, verification in the app, shipped key for the project server | 1 week |
| 3 | Android: shop tab in a group, item editor, basket, order screens, location steps | 2–3 weeks |
| 4 | Drivers: role, assignment, ETA flow (Android) | 1 week |
| 5 | Desktop screens; terminal commands (`/shop`, `/order`) | 1–2 weeks |
| 6 | Device testing on two phones and a laptop; docs; release notes | 1 week |

Each stage ships behind a setting that is **off by default** until device
tests pass, as calls and groups did.

---

## 14. Business model

* **The software stays open source and free**, including the shop feature.
* **Income:** a monthly fee for a **hosted, maintained server for a business**
  (their own I2P/XMPP server with shops enabled and their attestation key
  managed), or for setting one up on their machine. The customer is an
  identified business that pays the project; that satisfies "know your
  trader" by construction and keeps the project out of the shops' sales.
* **Not:** a fee per shop on a shared anonymous server, a cut of sales, or
  any payment handling.
* Before the first paid customer: terms of service, a privacy notice, and a
  short legal consultation in the maintainer's country.

---

## 15. Decisions for the owner

1. **Shop identity:** shops identified to the server operator (attestation),
   buyers private. *Recommended; the rest of this design depends on it.*
2. **No link to payments:** the shop feature never touches the Monero
   courier or `/tip`. *Recommended.*
3. **First version without drivers?** Shop + delivery quotes + orders first,
   drivers in stage 4. *Recommended: it proves the core with less to test.*
4. **Retention defaults:** buyer 90 days (coarse area), exact pin 24 h,
   shop 90 days. Adjust?
5. **Paid tier:** hosting and support for identified businesses, after a legal
   consultation. *Recommended.*
