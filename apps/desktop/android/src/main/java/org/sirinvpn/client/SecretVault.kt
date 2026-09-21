package org.sirinvpn.client

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class SecretVault(context: Context) {
    private val directory = File(context.noBackupFilesDir, "credentials").apply { mkdirs() }
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private val alias = "sirinvpn.credentials.v1"
    private fun key(): SecretKey {
        (keyStore.getKey(alias, null) as? SecretKey)?.let { return it }
        check(directory.listFiles()?.none { it.name.endsWith(".enc") } != false) { "Existing encrypted credentials require their original Keystore key" }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
            init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256).setUserAuthenticationRequired(false).build())
            generateKey()
        }
    }
    private fun file(reference: String): AtomicFile {
        require(reference.matches(Regex("[a-zA-Z0-9-]{1,128}")))
        return AtomicFile(File(directory, "$reference.enc"))
    }
    @Synchronized fun put(reference: String, value: ByteArray) {
        require(value.size <= 73728)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key())
        cipher.updateAAD(reference.toByteArray(Charsets.UTF_8))
        val encrypted = byteArrayOf(1) + cipher.iv + cipher.doFinal(value)
        val file = file(reference)
        val stream = file.startWrite()
        try { stream.write(encrypted); file.finishWrite(stream) }
        catch (error: Exception) { file.failWrite(stream); throw error }
    }
    @Synchronized fun get(reference: String): ByteArray? {
        val file = file(reference)
        if (!file.baseFile.exists()) return null
        require(file.baseFile.length() <= 73760)
        val bytes = file.readFully()
        require(bytes.size >= 29 && bytes[0] == 1.toByte())
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        // A missing/invalidated key must not replace unreadable encrypted state.
        val existing = keyStore.getKey(alias, null) as? SecretKey ?: error("Credential key unavailable")
        cipher.init(Cipher.DECRYPT_MODE, existing, GCMParameterSpec(128, bytes.copyOfRange(1, 13)))
        cipher.updateAAD(reference.toByteArray(Charsets.UTF_8))
        return cipher.doFinal(bytes, 13, bytes.size - 13)
    }
    @Synchronized fun delete(reference: String) { file(reference).delete() }
}
