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
        val files = checkNotNull(directory.listFiles()) { "Credential directory unavailable" }
        check(files.none { it.name.endsWith(".enc") || it.name.endsWith(".enc.bak") || it.name.endsWith(".enc.new") }) { "Existing encrypted credentials require their original Keystore key" }
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
    private fun deletionRequested(reference: String) = listOf(".deleted", ".deleted.bak", ".deleted.new").any { File(directory, reference + it).exists() }
    @Synchronized fun put(reference: String, value: ByteArray) {
        val file = file(reference) // Validate before accessing or generating a Keystore key.
        check(!deletionRequested(reference)) { "Credential deletion was requested" }
        require(value.size <= 73728)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key())
        cipher.updateAAD(reference.toByteArray(Charsets.UTF_8))
        val encrypted = byteArrayOf(1) + cipher.iv + cipher.doFinal(value)
        val stream = file.startWrite()
        try {
            stream.write(encrypted)
            stream.fd.sync()
            file.finishWrite(stream)
        } catch (error: Exception) {
            file.failWrite(stream)
            throw error
        }
        check(read(file).contentEquals(encrypted)) { "Credential write was not acknowledged" }
        syncDirectory()
    }
    @Synchronized fun get(reference: String): ByteArray? {
        val file = file(reference)
        if (deletionRequested(reference)) return null
        val bytes = try {
            read(file)
        } catch (missing: java.io.FileNotFoundException) {
            check(listOf(".enc", ".enc.bak", ".enc.new").none { File(directory, reference + it).exists() }) { "Credential storage is incomplete" }
            return null
        }
        require(bytes.size >= 29 && bytes[0] == 1.toByte())
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        // A missing/invalidated key must not replace unreadable encrypted state.
        val existing = keyStore.getKey(alias, null) as? SecretKey ?: error("Credential key unavailable")
        cipher.init(Cipher.DECRYPT_MODE, existing, GCMParameterSpec(128, bytes.copyOfRange(1, 13)))
        cipher.updateAAD(reference.toByteArray(Charsets.UTF_8))
        return cipher.doFinal(bytes, 13, bytes.size - 13)
    }
    private fun read(file: AtomicFile): ByteArray =
        file.openRead().use { input ->
            val output = java.io.ByteArrayOutputStream()
            val buffer = ByteArray(8192)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                require(output.size() + count <= 73760)
                output.write(buffer, 0, count)
            }
            output.toByteArray()
        }

    @Synchronized fun delete(reference: String) {
        val encrypted = file(reference)
        val marker = AtomicFile(File(directory, "$reference.deleted"))
        val stream = marker.startWrite()
        try {
            stream.write(byteArrayOf(1))
            stream.fd.sync()
            marker.finishWrite(stream)
        } catch (error: Exception) {
            marker.failWrite(stream)
            throw error
        }
        check(marker.baseFile.isFile && marker.baseFile.length() == 1L) { "Credential deletion intent was not stored" }
        syncDirectory()
        encrypted.delete()
        check(listOf(".enc", ".enc.bak", ".enc.new").none { File(directory, reference + it).exists() }) { "Credential cleanup incomplete; retry removal" }
        syncDirectory()
    }
    private fun syncDirectory() {
        val descriptor = android.system.Os.open(directory.absolutePath, android.system.OsConstants.O_RDONLY or android.system.OsConstants.O_NOFOLLOW, 0)
        try {
            check(android.system.OsConstants.S_ISDIR(android.system.Os.fstat(descriptor).st_mode))
            android.system.Os.fsync(descriptor)
        } finally {
            android.system.Os.close(descriptor)
        }
    }
}
