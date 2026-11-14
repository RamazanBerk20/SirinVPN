package org.sirinvpn.client

import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.Settings
import java.io.File

object ApkInstaller {
    fun install(context:Context,path:String) {
        check(context.packageManager.canRequestPackageInstalls())
        val file=File(path).canonicalFile
        require(file.path.startsWith(context.noBackupFilesDir.canonicalPath+"/") && file.isFile)
        // SigningInfo carries the lineage checks below; Android 12's archive parser fills it from this flag alone.
        val flags=PackageManager.GET_SIGNING_CERTIFICATES
        val candidate=context.packageManager.getPackageArchiveInfo(file.path,flags) ?: error("Invalid APK")
        val installed=context.packageManager.getPackageInfo(context.packageName,flags)
        require(candidate.packageName==context.packageName && candidate.longVersionCode>installed.longVersionCode)
        val current=requireNotNull(installed.signingInfo) { "Installed signature unavailable" }
        val incoming=requireNotNull(candidate.signingInfo) { "APK signature unavailable" }
        val signers=current.apkContentsSigners
        require(signers.isNotEmpty())
        if(current.hasMultipleSigners() || incoming.hasMultipleSigners())
            require(signers.toSet()==incoming.apkContentsSigners.toSet())
        else require(incoming.signingCertificateHistory.any {it==signers.single()})
        val installer=context.packageManager.packageInstaller
        check(installer.mySessions.isEmpty()) { "An Android installation is already pending" }
        val parameters=PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply {
            setAppPackageName(context.packageName);setSize(file.length())
            setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_REQUIRED)
        }
        val id=installer.createSession(parameters)
        try {
            installer.openSession(id).use { session ->
                session.openWrite("base.apk",0,file.length()).use { output -> file.inputStream().use { it.copyTo(output) };session.fsync(output) }
                val result=PendingIntent.getBroadcast(context,id,Intent(context,ApkInstallResult::class.java),
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE)
                session.commit(result.intentSender)
            }
        } catch (error:Exception) { installer.abandonSession(id);throw error }
    }
    /** Android asks once per app: "Install unknown apps". Opens that setting when it's off. */
    fun ensurePermission(context:Context):Boolean {
        if(context.packageManager.canRequestPackageInstalls()) return true
        val settings=Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,Uri.parse("package:"+context.packageName))
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        try { context.startActivity(settings) } catch (_:Exception) { /* The error text names the setting. */ }
        return false
    }
    fun abandon(context:Context) {
        val installer=context.packageManager.packageInstaller
        for(session in installer.mySessions) installer.abandonSession(session.sessionId)
    }
}
class ApkInstallResult : BroadcastReceiver() {
    override fun onReceive(receiverContext:Context,intent:Intent) {
        val context=AppLanguage.wrap(receiverContext.applicationContext)
        val status=intent.getIntExtra(PackageInstaller.EXTRA_STATUS,PackageInstaller.STATUS_FAILURE)
        val manager=context.getSystemService(NotificationManager::class.java)
        if(status==PackageInstaller.STATUS_PENDING_USER_ACTION) {
            @Suppress("DEPRECATION") val consent=intent.getParcelableExtra<Intent>(Intent.EXTRA_INTENT) ?: return
            consent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            VpnNotifications.channels(context)
            manager.notify(VpnNotifications.UPDATE_ID,Notification.Builder(context,VpnNotifications.UPDATE_CHANNEL).setSmallIcon(R.drawable.ic_sirin_vpn)
                .setBadgeIconType(Notification.BADGE_ICON_NONE)
                .setContentTitle(context.getString(R.string.notification_update_title)).setContentText(context.getString(R.string.notification_update_text))
                .setContentIntent(PendingIntent.getActivity(context,VpnNotifications.UPDATE_ID,consent,PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)).setAutoCancel(true).build())
            try { context.startActivity(consent) } catch (_:Exception) { /* The notification retains Android's approval action. */ }
        } else manager.cancel(VpnNotifications.UPDATE_ID)
    }
}
