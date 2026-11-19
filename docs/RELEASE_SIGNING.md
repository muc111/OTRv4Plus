<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright (C) 2025-2026 muc111 -->

# The release signing key

Android accepts an update only if it is signed with the same key as the app
already installed. Until a release key is set up, CI signs every build with a
throwaway debug key, and the release notes say so. This page is the one-time
setup. It is the owner's to do: nobody else should ever hold this key.

**Read this first.**

- **Losing the key or its password means no update can ever be installed
  over an existing one.** Everyone would have to uninstall and reinstall,
  which deletes their identity keys on that phone. Make two offline copies
  before using it.
- **Switching from the debug key is the same break, once.** The first build
  signed with your key will not install over a debug-signed one. Do it
  before there are users to disturb.
- **Never commit the keystore, and never paste its password** into a chat,
  an issue or an AI assistant. It goes into GitHub's secret store and
  nowhere else online.

## 1. Create the keystore

On your own machine (not the server), with a JDK installed
(`sudo apt install default-jdk-headless`):

```bash
keytool -genkeypair -v \
  -keystore otrv4plus-release.jks \
  -alias otrv4plus \
  -keyalg RSA -keysize 4096 \
  -validity 10000
```

It asks for a password and a name. Use a long password from a password
manager. The name fields are shown in the certificate; `CN=OTRv4Plus` and
nothing else is enough. Current `keytool` writes a PKCS12 file, in which the
key's password is the keystore's password: there is one password, used twice
below.

Write down the certificate's fingerprint. It is how anyone can check a
download is yours:

```bash
keytool -list -v -keystore otrv4plus-release.jks -alias otrv4plus | grep SHA256
```

## 2. Back it up, offline, twice

Copy `otrv4plus-release.jks` to two encrypted places that are not this
machine and not a cloud drive (two USB sticks kept apart, for example), and
keep the password where the file is not.

## 3. Give CI the key

Encode the file as one line:

```bash
base64 -w0 otrv4plus-release.jks > keystore.b64      # macOS: base64 -i otrv4plus-release.jks | tr -d '\n' > keystore.b64
```

On GitHub: the repository → **Settings** → **Secrets and variables** →
**Actions** → **New repository secret**. Add four:

| Name | Value |
|---|---|
| `OTRV4PLUS_RELEASE_KEYSTORE_B64` | the contents of `keystore.b64` |
| `OTRV4PLUS_RELEASE_STORE_PASSWORD` | the password |
| `OTRV4PLUS_RELEASE_KEY_ALIAS` | `otrv4plus` |
| `OTRV4PLUS_RELEASE_KEY_PASSWORD` | the same password |

Or from a terminal with the GitHub CLI, which never shows the values:

```bash
gh secret set OTRV4PLUS_RELEASE_KEYSTORE_B64 < keystore.b64
gh secret set OTRV4PLUS_RELEASE_KEY_ALIAS --body otrv4plus
gh secret set OTRV4PLUS_RELEASE_STORE_PASSWORD      # prompts; paste the password
gh secret set OTRV4PLUS_RELEASE_KEY_PASSWORD        # prompts; the same
```

Then remove the working copies from this machine:

```bash
shred -u keystore.b64
```

GitHub never shows a secret again after it is saved, masks it in logs, and
does not give it to pull requests from forks. Anyone with **write** access to
the repository can still run a workflow that uses it, so keep write access to
yourself.

## 4. Check it took

Push any commit. In the Android workflow, the job "Assemble and inspect the
release APK" should print `signing with the owner's release key`, and its
`signing-key.txt` artifact should say `owner`. Then, on the downloaded APK:

```bash
apksigner verify --print-certs app-release.apk | grep SHA-256
```

The digest must equal the fingerprint from step 1 (same bytes; `keytool`
prints them with colons). Publish that fingerprint in the README and the
release notes, so a download can be checked against it.

## If the key is ever exposed

Whoever has it can sign an app that installs over yours. Android has no way
to revoke a signing key for an app installed outside an app store. Generate a new key, publish its
fingerprint and the reason, and tell users to reinstall from the new build.
That cost is why the key lives offline and its only online copy is the
encrypted secret.
