# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Credentials and history that survive the process, and what they must not do.

The behaviour is covered by executed JVM tests -- `CredentialStoreTest`,
`VaultTest`, `PersistentMessageStoreTest`, `MessageCodecTest`. What is here is
the part no unit test can see: that the platform half uses the Keystore rather
than a plaintext file, that it degrades to remembering NOTHING rather than to
writing in the clear, and that the service rather than a screen owns the
drain loop.
"""

import io
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAIN = os.path.join(ROOT, "android", "app", "src", "main")
JAVA = os.path.join(MAIN, "java", "org", "otrv4plus", "android")
UNIT = os.path.join(ROOT, "android", "app", "src", "test", "java", "org",
                    "otrv4plus", "android")


def _read(*parts):
    with io.open(os.path.join(*parts), encoding="utf-8") as fh:
        return fh.read()


def _code_only(text):
    text = re.sub(r"/\*(?:.|\n)*?\*/", " ", text)
    text = re.sub(r"//[^\n]*", "", text)
    return re.sub(r'"(?:\\.|[^"\\\n])*"', '""', text)


@pytest.fixture(scope="module")
def vault():
    return _read(JAVA, "security", "KeystoreVault.kt")


@pytest.fixture(scope="module")
def service():
    return _read(JAVA, "connection", "OtrConnectionService.kt")


class TestTheVaultUsesThePlatform:

    def test_the_key_lives_in_the_android_keystore(self, vault):
        assert '"AndroidKeyStore"' in vault or "AndroidKeyStore" in vault
        assert "KeyGenParameterSpec" in vault

    def test_it_is_aes_gcm(self, vault):
        assert "AES/GCM/NoPadding" in vault
        assert "BLOCK_MODE_GCM" in vault
        assert "setKeySize(256)" in vault

    def test_the_entry_name_is_authenticated(self, vault):
        """So a record sealed under one name cannot be opened under another --
        stored credentials cannot be replayed as stored history."""
        assert vault.count("updateAAD") >= 2

    def test_a_fresh_iv_every_time(self, vault):
        assert "setRandomizedEncryptionRequired(true)" in vault

    def test_it_does_not_require_the_user_to_be_present(self, vault):
        """The load-bearing line for background reconnect: the service
        reconnects with the screen off, so the key cannot be gated on
        authentication."""
        assert "setUserAuthenticationRequired(false)" in vault

    def test_failing_to_open_degrades_to_remembering_nothing(self, vault):
        """NEVER to a plaintext file. A device whose Keystore is unavailable is
        the last place to start writing passwords in the clear."""
        block = vault[vault.index("fun open(context: Context)"):]
        block = block[:block.index("private fun loadOrCreateKey")]
        assert "InMemoryVault()" in block

    def test_there_is_no_plaintext_fallback_anywhere(self, vault):
        code = _code_only(vault)
        for banned in ("SharedPreferences", "openFileOutput", "FileWriter",
                       "PrintWriter"):
            assert banned not in code, banned

    def test_a_record_that_will_not_open_reads_as_absent(self, vault):
        block = vault[vault.index("override fun get("):]
        block = block[:block.index("override fun remove(")]
        assert "null" in block
        assert "catch" in block

    def test_writes_are_atomic(self, vault):
        """A kill halfway through must leave the previous record, not a
        truncated one."""
        assert "renameTo" in vault


class TestCredentialsAreNotExposed:

    def test_the_password_is_never_logged(self):
        for name in ("KeystoreVault.kt", "CredentialStore.kt", "Vault.kt"):
            code = _code_only(_read(JAVA, "security", name))
            assert "Log." not in code, name
            assert "println" not in code, name

    def test_the_service_does_not_log_the_password(self, service):
        code = _code_only(service)
        for line in code.splitlines():
            if "password" in line.lower():
                assert "Log." not in line, line

    def test_credentials_tostring_redacts(self):
        source = _read(JAVA, "security", "CredentialStore.kt")
        block = source[source.index("class Credentials("):]
        block = block[:block.index("interface CredentialStore")]
        assert "redacted" in block

    def test_the_password_is_removed_from_the_intent(self, service):
        assert "removeExtra(EXTRA_PASSWORD)" in service

    def test_the_password_does_not_reach_compose_state(self):
        """The ViewModel hands it to the service and keeps no copy."""
        view_model = _code_only(_read(JAVA, "ConnectionViewModel.kt"))
        assert "mutableStateOf" in view_model
        assert not re.search(r"var\s+password\s+by\s+mutableStateOf", view_model)

    def test_logout_clears_the_credentials_and_the_history(self, service):
        block = service[service.index("ACTION_LOGOUT ->"):]
        block = block[:block.index("ACTION_START ->")]
        assert "credentials.clear()" in block
        assert "messages.clear()" in block


class TestTheServiceOwnsTheConversation:
    """The reason background delivery could not work before.

    The engine's event queue is DESTRUCTIVE -- a drain removes what it returns
    -- so whoever drains it is the only one who will ever see those events. A
    ViewModel does not exist while the UI is gone.
    """

    def test_the_service_drains_the_queue(self, service):
        assert "core.drainEvents()" in service
        assert "startDraining" in service

    def test_the_service_owns_the_chat_state(self, service):
        assert "val chat: ChatState by lazy" in service

    def test_the_service_owns_a_durable_store(self, service):
        assert "PersistentMessageStore(vault)" in service

    def test_the_view_model_does_not_drain(self):
        code = _code_only(_read(JAVA, "chat", "ChatViewModel.kt"))
        for pulled in ("drainEvents", "eventsDropped", "connectionStatus",
                       "contacts()"):
            assert pulled not in code, (
                "ChatViewModel reads %s; two readers of a destructive queue "
                "lose every other message" % pulled)

    def test_the_view_model_does_not_build_a_store(self):
        code = _code_only(_read(JAVA, "chat", "ChatViewModel.kt"))
        assert "InMemoryMessageStore" not in code
        assert "PersistentMessageStore" not in code
        assert "ChatState(" not in code

    def test_draining_survives_a_disconnect(self, service):
        """A message already in the queue when the stream dropped is still
        worth having, so the drain loop is stopped only when the service is."""
        stop = service[service.index("fun stopConnection("):]
        stop = stop[:stop.index("private fun startDraining")]
        assert "drainer" not in stop
        destroy = service[service.index("override fun onDestroy"):]
        destroy = destroy[:destroy.index("\n    //")]
        assert "drainer?.cancel()" in destroy


class TestHistoryIsSealedNotPlaintext:

    def test_the_store_writes_through_the_vault(self):
        store = _read(JAVA, "chat", "PersistentMessageStore.kt")
        assert "vault.put" in store
        assert "vault.get" in store

    def test_it_introduces_no_database_and_no_plaintext_file(self):
        store = _code_only(_read(JAVA, "chat", "PersistentMessageStore.kt"))
        for banned in ("Room", "SQLite", "openFileOutput", "SharedPreferences",
                       "FileWriter"):
            assert banned not in store, banned

    def test_the_entry_name_is_not_the_contact(self):
        """Names are not sealed -- only values are -- so a directory listing
        must not read as a contact list."""
        store = _read(JAVA, "chat", "PersistentMessageStore.kt")
        block = store[store.index("fun entryFor("):]
        block = block[:block.index("internal fun stableHash")]
        assert "stableHash" in block

    def test_no_cryptographic_material_is_persisted(self):
        """The security label is the WORD `ENCRYPTED`, not a key. A ratchet
        state has never been near this class and must not arrive."""
        codec = _code_only(_read(JAVA, "chat", "MessageCodec.kt"))
        for banned in ("key", "Key", "secret", "ratchet", "session"):
            assert banned not in codec, banned

    def test_the_never_persisted_categories_are_still_named(self):
        secure = _read(JAVA, "security", "SecureStore.kt")
        assert "NEVER_PERSISTED" in secure
        assert "otr.ratchet.state" in secure
        assert "otr.session.keys" in secure

    def test_an_unreadable_label_is_not_read_as_encrypted(self):
        codec = _read(JAVA, "chat", "MessageCodec.kt")
        block = codec[codec.index("security = SecurityLabel.entries"):]
        block = block[:block.index(")")]
        assert "SecurityLabel.UNKNOWN" in block
