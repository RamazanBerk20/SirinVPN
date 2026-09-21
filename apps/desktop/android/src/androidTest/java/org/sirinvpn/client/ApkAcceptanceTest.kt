package org.sirinvpn.client

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Test
import org.junit.Assert.*
import org.junit.runner.RunWith
import java.io.File

/** Candidate APKs are debug-signed fixtures; the host cancels Android's install dialog. */
@RunWith(AndroidJUnit4::class)
class ApkAcceptanceTest {
    @Test fun candidateValidationAndUserCancellation() {
        assertTrue(BuildConfig.DEBUG)
        assertTrue(android.os.Build.HARDWARE in setOf("ranchu","goldfish"))
        val instrumentation=InstrumentationRegistry.getInstrumentation()
        val context=instrumentation.targetContext
        assertTrue(context.packageManager.canRequestPackageInstalls())
        val installer=context.packageManager.packageInstaller
        assertTrue(installer.mySessions.isEmpty())
        val rejected=File(context.noBackupFilesDir,"acceptance-rejected.apk")
        val candidate=File(context.noBackupFilesDir,"acceptance-update.apk")
        val unsigned=File(context.noBackupFilesDir,"acceptance-unsigned.apk")
        assertTrue(candidate.isFile && unsigned.isFile)
        val installedVersion=context.packageManager.getPackageInfo(context.packageName,0).longVersionCode
        try {
            File(context.applicationInfo.sourceDir).copyTo(rejected,true)
            assertTrue("The current version cannot be installed as an update",runCatching {ApkInstaller.install(context,rejected.path)}.isFailure)
            File(instrumentation.context.applicationInfo.sourceDir).copyTo(rejected,true)
            assertTrue("A different package cannot replace SirinVPN",runCatching {ApkInstaller.install(context,rejected.path)}.isFailure)
            assertTrue("Unsigned APK rejected",runCatching {ApkInstaller.install(context,unsigned.path)}.isFailure)
            assertTrue(installer.mySessions.isEmpty())
            instrumentation.startActivitySync(android.content.Intent(context,MainActivity::class.java).addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK))
            ApkInstaller.install(context,candidate.path)
            assertTrue("Android installation session exists",installer.mySessions.isNotEmpty())
            println("APK validation passed; waiting for host to cancel Android approval")
            val deadline=android.os.SystemClock.elapsedRealtime()+60000
            while(installer.mySessions.isNotEmpty() && android.os.SystemClock.elapsedRealtime()<deadline) Thread.sleep(200)
            assertTrue("User cancellation removes the session",installer.mySessions.isEmpty())
            assertEquals("Cancellation preserved the installed version",installedVersion,context.packageManager.getPackageInfo(context.packageName,0).longVersionCode)
        } finally {
            ApkInstaller.abandon(context)
            rejected.delete();candidate.delete();unsigned.delete()
        }
    }
}
