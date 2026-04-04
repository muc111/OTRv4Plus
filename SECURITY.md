```
# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| latest release (v10.2+) | ✅ |
| older releases | ❌ |

Only the latest stable release receives security updates.

## Reporting a vulnerability

**Do not open a public GitHub issue.**

Use GitHub's private vulnerability reporting:

1. Go to the **Security** tab on this repository
2. Click **Report a vulnerability**
3. Fill in the details

Please include:
- A clear description of the issue
- Steps to reproduce
- Potential impact
- Suggested fix (if available)

## What to expect

- Acknowledgment within 48 hours
- Fix within 14 days for critical issues (key compromise, plaintext recovery)
- Public disclosure after fix is released, with credit (unless anonymity requested)

## Scope

The following are in scope:
- Cryptographic weaknesses (DAKE, ratchet, SMP, ring signatures)
- Key material leaks (memory, disk, network)
- Authentication bypasses
- Plaintext recovery attacks

The following are out of scope:
- Endpoint compromise (rooted device, malware)
- I2P/Tor network-level attacks
- Social engineering

## Responsible disclosure

Please do not test on live IRC networks without permission.
If you find a vulnerability in a dependency (OpenSSL, cryptography),
report it to them first.
```