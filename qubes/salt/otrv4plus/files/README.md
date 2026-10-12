# Files for the otrv4plus Salt formula

* `30-otrv4plus.policy` — dom0 qrexec policy (installed by `dom0.sls`).
* `i2pd.conf` — sys-i2p's router configuration (installed by `i2p-tpl.sls`).
* `otrv4plus-release.gpg` — **not in the repository; you provide it.** The
  public half of the release key in `otr-sign`, exported in binary form:

  ```
  # in otr-sign
  gpg --export <FINGERPRINT> > otrv4plus-release.gpg
  ```

  Bring it to dom0 the same way as the formula itself (README, step 2) and
  compare its fingerprint with `gpg --show-keys otrv4plus-release.gpg`
  before applying a template state. The template states refuse any
  package whose signature does not verify against this file.
