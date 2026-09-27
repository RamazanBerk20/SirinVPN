package org.sirinvpn.client

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class VaultAcceptanceTest {
    @Test fun missingKeyDoesNotReplaceEncryptedIdentity() {
        assertTrue(BuildConfig.DEBUG)
        assertTrue(android.os.Build.HARDWARE in setOf("ranchu", "goldfish"))
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val directory = File(context.noBackupFilesDir, "credentials")
        val vault = SecretVault(context)
        // Only the fresh AVD fixture may invalidate this app's key.
        check(directory.listFiles()!!.none { it.name.endsWith(".enc") })
        val reference = "acceptance-${UUID.randomUUID()}"
        val replacement = "acceptance-${UUID.randomUUID()}"
        vault.put(reference, "synthetic invalidation test".toByteArray())
        val file = File(directory, "$reference.enc")
        val original = file.readBytes()
        try {
            java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                .deleteEntry("sirinvpn.credentials.v1")
            assertTrue(runCatching { vault.get(reference) }.isFailure)
            assertTrue(runCatching { vault.put(replacement, byteArrayOf(1)) }.isFailure)
            assertArrayEquals(original, file.readBytes())
            assertFalse(File(directory, "$replacement.enc").exists())
        } finally {
            vault.delete(reference)
            vault.delete(replacement)
        }
    }

    @Test fun authenticatedStorage() {
        assertTrue(BuildConfig.DEBUG)
        assertTrue(android.os.Build.HARDWARE in setOf("ranchu","goldfish"))
        val context=InstrumentationRegistry.getInstrumentation().targetContext
        val vault=SecretVault(context)
        val first="acceptance-${UUID.randomUUID()}"
        val second="acceptance-${UUID.randomUUID()}"
        val directory=File(context.noBackupFilesDir,"credentials")
        val file=File(directory,"$first.enc")
        val value="Disposable acceptance value ${UUID.randomUUID()}".toByteArray()
        try {
            vault.put(first,value)
            assertArrayEquals(value,vault.get(first))
            val initial=file.readBytes()
            assertFalse(String(initial,Charsets.ISO_8859_1).contains(String(value)))
            vault.put(first,value)
            assertFalse(initial.contentEquals(file.readBytes()))
            File(directory,"$second.enc").writeBytes(initial)
            assertTrue("AAD must bind ciphertext to its reference",runCatching {vault.get(second)}.isFailure)
            initial[initial.lastIndex]=(initial.last().toInt() xor 1).toByte()
            file.writeBytes(initial)
            assertTrue("Tampered ciphertext must fail authentication",runCatching {vault.get(first)}.isFailure)
            assertArrayEquals("Failure must preserve the unreadable data",initial,file.readBytes())
            assertTrue(runCatching {vault.put("../escape",value)}.isFailure)
            assertTrue(runCatching {vault.put(first,ByteArray(73729))}.isFailure)
        } finally {
            value.fill(0);vault.delete(first);vault.delete(second)
        }
        assertNull(vault.get(first))
        assertTrue("Deletion cannot be undone by a stale write", runCatching { vault.put(first, byteArrayOf(1)) }.isFailure)
    }

    @Test fun incompleteDeletionAndInterruptedWriteAreNotAbsence() {
        assertTrue(BuildConfig.DEBUG)
        assertTrue(android.os.Build.HARDWARE in setOf("ranchu", "goldfish"))
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val vault = SecretVault(context)
        val reference = "acceptance-${UUID.randomUUID()}"
        val directory = File(context.noBackupFilesDir, "credentials")
        val blocked = File(directory, "$reference.enc").apply { mkdirs() }
        val child = File(blocked, "fixture").apply { writeText("synthetic") }
        try {
            assertTrue(runCatching { vault.delete(reference) }.isFailure)
            assertNull(vault.get(reference))
            assertTrue(runCatching { vault.put(reference, byteArrayOf(1)) }.isFailure)
        } finally {
            check(child.delete()); check(blocked.delete()); vault.delete(reference)
        }
        vault.delete(reference)
    }
}
