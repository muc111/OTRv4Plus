// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * [Vault] over the AndroidKeyStore.
 *
 * NO DECISIONS LIVE HERE. Everything about what is stored, when it is cleared
 * and how it is encoded is above this line in plain Kotlin with real tests;
 * this class exists to call `Cipher.doFinal` and write a file, because
 * `AndroidKeyStore` is a platform provider that cannot be constructed off a
 * device.
 *
 * WHAT IT PROTECTS AGAINST, AND WHAT IT DOES NOT
 * ----------------------------------------------
 * The key is generated in the Keystore and never leaves it -- on most modern
 * hardware it lives in a TEE or a dedicated security chip, and
 * `isInsideSecureHardware` reports which. So:
 *
 *   * a file pulled off the device, out of a backup, or off a desoldered flash
 *     chip is ciphertext, and stays ciphertext;
 *   * code running AS THIS APP on an unlocked phone can ask the Keystore to
 *     decrypt, and will get plaintext. That is inherent: the service has to
 *     reconnect while nobody is looking at the screen, so the key cannot be
 *     gated on the user being present.
 *
 * `setUserAuthenticationRequired(false)` is therefore deliberate and is the
 * whole reason background reconnect works. A passphrase-derived key would
 * close the second gap and break the first requirement; when the app unlock
 * lands it can supply a second layer, and nothing above this class changes.
 *
 * `ANDROID_STORAGE_AUDIT.md` records this distinction so "encrypted at rest"
 * is not read as more than it buys.
 *
 * THE RECORD
 * ----------
 *     iv(12) || ciphertext || tag(16)
 *
 * with the entry NAME as additional authenticated data, so a record sealed
 * under one name cannot be opened under another -- stored credentials cannot
 * be replayed as stored history, or the reverse.
 */
class KeystoreVault private constructor(
    private val key: SecretKey,
    private val directory: File,
) : Vault {

    override fun put(name: String, bytes: ByteArray) {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        cipher.updateAAD(name.toByteArray(Charsets.UTF_8))
        val sealed = cipher.doFinal(bytes)
        val record = ByteArray(cipher.iv.size + sealed.size)
        System.arraycopy(cipher.iv, 0, record, 0, cipher.iv.size)
        System.arraycopy(sealed, 0, record, cipher.iv.size, sealed.size)
        // Written to a temporary file and renamed, so a kill halfway through
        // leaves the previous record rather than a truncated one.
        val target = fileFor(name)
        val scratch = File(target.parentFile, target.name + ".tmp")
        scratch.writeBytes(record)
        if (!scratch.renameTo(target)) {
            target.writeBytes(record)
            scratch.delete()
        }
    }

    override fun get(name: String): ByteArray? {
        val file = fileFor(name)
        if (!file.exists()) return null
        return try {
            val record = file.readBytes()
            if (record.size <= IV_BYTES) return null
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(
                Cipher.DECRYPT_MODE, key,
                GCMParameterSpec(TAG_BITS, record, 0, IV_BYTES))
            cipher.updateAAD(name.toByteArray(Charsets.UTF_8))
            cipher.doFinal(record, IV_BYTES, record.size - IV_BYTES)
        } catch (e: Exception) {
            // Undifferentiated on purpose, and it is the contract: a wrong
            // key, a tampered record, a truncated file and a key the user
            // invalidated by changing their lock screen all mean "you do not
            // have this data". Behaving as though it was never there is the
            // only safe response, and is what the caller is written for.
            null
        }
    }

    override fun remove(name: String) {
        runCatching { fileFor(name).delete() }
    }

    override fun clear() {
        runCatching { directory.listFiles()?.forEach { it.delete() } }
    }

    /**
     * The file for [name].
     *
     * Hex of the UTF-8 bytes rather than the name itself: a vault entry name
     * may contain anything the caller chose, and a filename must not be able
     * to contain a path separator. This is escaping, not secrecy -- callers
     * that need the NAME itself to reveal nothing hash it before they get
     * here, as `PersistentMessageStore` does.
     */
    private fun fileFor(name: String): File =
        File(directory, name.toByteArray(Charsets.UTF_8)
            .joinToString("") { "%02x".format(it) })

    companion object {
        private const val KEYSTORE = "AndroidKeyStore"
        private const val ALIAS = "otrv4plus.vault.v1"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val IV_BYTES = 12
        private const val TAG_BITS = 128

        /**
         * Open the vault, or fall back to one that remembers nothing.
         *
         * NEVER falls back to a plaintext file. An app that cannot reach the
         * Keystore -- a device with a broken provider, a user who reset their
         * lock screen and invalidated the key -- must degrade to "nothing is
         * remembered", because the alternative is writing the password and
         * every message body to disk in the clear on exactly the devices least
         * able to protect them.
         */
        fun open(context: Context): Vault = try {
            val directory = File(context.filesDir, "vault").apply { mkdirs() }
            KeystoreVault(loadOrCreateKey(), directory)
        } catch (e: Exception) {
            InMemoryVault()
        }

        /**
         * Wipe & Exit: delete the sealing key, then the records.
         *
         * THE KEY FIRST, because the key is the erasure. Every record in the
         * vault is AES-256-GCM under a key that lives in the AndroidKeyStore
         * (in a TEE or secure element where the device has one) and has never
         * existed outside it. Once the entry is deleted no record can be
         * opened again -- not from this app, not from a backup, not from a
         * block the flash controller has not erased yet. Deleting the files
         * afterwards is tidiness; it is not what the guarantee rests on, and
         * on flash it could not carry one.
         *
         * Returns whether the key is confirmed gone. The next [open] generates
         * a fresh key, so a relaunch starts from an empty vault.
         */
        fun destroy(context: Context): Boolean {
            val keyGone = runCatching {
                val store = KeyStore.getInstance(KEYSTORE).apply { load(null) }
                if (store.containsAlias(ALIAS)) store.deleteEntry(ALIAS)
                !store.containsAlias(ALIAS)
            }.getOrDefault(false)
            runCatching { File(context.filesDir, "vault").deleteRecursively() }
            return keyGone
        }

        private fun loadOrCreateKey(): SecretKey {
            val store = KeyStore.getInstance(KEYSTORE).apply { load(null) }
            (store.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry)
                ?.let { return it.secretKey }

            val generator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
            generator.init(
                KeyGenParameterSpec.Builder(
                    ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    // FALSE, and this is the load-bearing line. The connection
                    // service reconnects while the screen is off and nobody is
                    // present; requiring authentication here would mean the
                    // password could not be read to reconnect with, which is
                    // the entire point of storing it.
                    .setUserAuthenticationRequired(false)
                    // Randomised IV comes from the Cipher, which is what the
                    // record format expects; letting the framework supply one
                    // would change the layout.
                    .setRandomizedEncryptionRequired(true)
                    .build()
            )
            return generator.generateKey()
        }
    }
}
