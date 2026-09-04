# Commercial licence

OTRv4+ is dual-licensed. You may use it under the **GNU Affero General Public
License v3** (see [LICENSE](LICENSE)) at no cost, or under a **commercial
licence** obtained from the copyright holder.

**You need a commercial licence if you want to distribute or operate OTRv4+, or
a work derived from it, without meeting the AGPL's source-disclosure
obligations.** If you are willing to release your own source under the AGPL,
you do not need one, and nothing here restricts you.

> This document describes the terms on offer. It is not itself a licence
> grant: a commercial licence exists only once a signed agreement is in place.
> It is also not legal advice — if the answer matters to your business, ask a
> lawyer rather than relying on this page.

---

## Which one applies to you

| What you are doing | AGPL-3.0 is enough | Commercial licence needed |
|---|---|---|
| Reading, studying, auditing the code | ✅ | |
| Running it for yourself or inside your organisation, unmodified | ✅ | |
| Research, teaching, publishing about it | ✅ | |
| Personal use, no distribution | ✅ | |
| Forking and publishing your fork under AGPL-3.0 | ✅ | |
| Shipping an app that includes it, with complete corresponding source under AGPL-3.0 | ✅ | |
| Shipping a **closed-source** app, product or appliance that includes it | | ✅ |
| Offering it, or a modified version, as a **hosted or managed service** without publishing that version's source | | ✅ |
| Linking it into proprietary code you are not willing to release | | ✅ |
| Removing attribution, or sublicensing it to your own customers under your terms | | ✅ |

Charging money is not itself the trigger. **The trigger is refusing the AGPL's
reciprocity** — keeping your source closed. The AGPL explicitly permits selling
copies (§4); what it does not permit is withholding the source from the people
who receive the software or use it over a network.

## What a commercial licence grants

Terms are agreed per deal, but the standard grant is:

- a non-exclusive, non-transferable right to use, modify and distribute OTRv4+
  in your own products **without** the AGPL's copyleft or §13 network
  provisions;
- the right to keep your own modifications and surrounding code proprietary;
- the right to sublicense the included OTRv4+ portions to your end users under
  your own terms.

Third-party components keep their own licences under either route — every
dependency is permissive (BSD-3-Clause, MIT, Apache-2.0, PSF), and their
attribution notices must be reproduced in your product regardless of which
OTRv4+ licence you hold. See [LICENSING_AUDIT.md](LICENSING_AUDIT.md).

## What it does not grant

A commercial licence is a licence, not a warranty and not a service contract.
It does not include support, maintenance, indemnity, an SLA, a security
guarantee, or any assurance of fitness. Those can be negotiated separately and
are priced separately.

**Read the "Honest caveats" section of the [README](README.md) before you build
anything on this.** OTRv4+ is an unaudited research prototype; its author is
not a cryptographer; the protocol composition has had no external review.
Paying for a licence changes the legal terms of your use. It does not change
any of that.

## Getting one

Open an issue at <https://github.com/muc111/OTRv4Plus/issues> titled
`Commercial licence enquiry`, or contact the copyright holder through the
address on the GitHub profile. Say what you intend to build, whether you will
distribute binaries or operate a service, and roughly at what scale — pricing
depends on those.

## Contributions

Contributions are accepted under the [CLA](CLA.md), which asks contributors to
grant the copyright holder the right to relicense their contribution. Without
that, a contributed patch could only ever be offered under the AGPL, and the
commercial option would decay one merge at a time. The CLA does not take your
copyright: you keep it, and your contribution stays available to everyone under
the AGPL like the rest of the project.
