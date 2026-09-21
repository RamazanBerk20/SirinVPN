package org.sirinvpn.client

import android.Manifest
import android.app.Activity
import android.app.NotificationManager
import android.app.StatusBarManager
import android.content.ComponentName
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.drawable.Icon
import android.net.VpnService
import android.os.Build
import android.provider.Settings
import android.webkit.WebView
import androidx.appcompat.app.AppCompatActivity
import androidx.activity.result.ActivityResult
import app.tauri.annotation.Command
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.TauriPlugin
import app.tauri.annotation.Permission
import app.tauri.annotation.PermissionCallback
import app.tauri.plugin.Plugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import org.json.JSONObject
import java.util.UUID

@TauriPlugin(permissions=[Permission(alias="camera",strings=[Manifest.permission.CAMERA]),Permission(alias="wifi",strings=[Manifest.permission.ACCESS_FINE_LOCATION,Manifest.permission.ACCESS_COARSE_LOCATION]),Permission(alias="notifications",strings=[Manifest.permission.POST_NOTIFICATIONS])])
class SirinPlugin(private val activity: Activity) : Plugin(activity) {
    private var link: ServiceLink? = null
    private var scanner: CodeScanner? = null
    private var listening = false
    private val listener = object : IStatus.Stub() {
        override fun changed(snapshot: String) { activity.runOnUiThread { trigger("status", JSObject(snapshot)) } }
    }
    override fun load(webView: WebView) {
        VpnNotifications.channels(activity)
        webView.settings.textZoom=(activity.resources.configuration.fontScale*100).toInt().coerceIn(50,300)
        attach()
    }
    override fun onResume() { attach(); scanner?.resumeCamera() }
    override fun onPause() { scanner?.pauseCamera(); detach() }
    override fun onDestroy(activity: AppCompatActivity) { scanner?.dismiss(); scanner = null; detach() }
    private fun attach() {
        if (link != null) return
        link = ServiceLink(activity,lost={
            listening=false
            activity.runOnUiThread { trigger("status", JSObject().put("status", JSONObject.NULL).put("phase","unknown").put("stale",true)) }
        },connected={ service -> service.subscribe(listener);listening=true }).also { it.bind() }
    }
    private fun detach() {
        if (listening) try { link?.ready?.getNow(null)?.unsubscribe(listener) } catch (_: Exception) {}
        listening = false; link?.close(); link = null
    }
    @Command fun call(invoke: Invoke) {
        val request = invoke.getArgs()
        val command = request.getString("command") ?: return reject(invoke,"Missing command")
        val args = request.optJSONObject("args") ?: JSONObject()
        if(command=="android_close_ui") {resolve(invoke);activity.moveTaskToBack(true);return}
        if(command=="android_share_document") {
            val uri=android.net.Uri.parse(args.optString("uri"))
            if(uri.scheme!="content") {reject(invoke,"Choose an encrypted document first.");return}
            attach()
            link!!.ready.whenComplete {control,error ->
                if(error!=null) reject(invoke,"The service is unavailable")
                else control.execute("authorize_document_share",args.toString(),UUID.randomUUID().toString(),-1,object:IResult.Stub(){
                    override fun complete(result:String) {activity.runOnUiThread {
                        if(JSONObject(result).has("error")) reject(invoke,"Export the encrypted file again before sharing it.")
                        else try {
                            val intent=Intent(Intent.ACTION_SEND).setType("application/octet-stream").putExtra(Intent.EXTRA_STREAM,uri)
                                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                            intent.clipData=android.content.ClipData.newRawUri("Encrypted SirinVPN backup",uri)
                            activity.startActivity(Intent.createChooser(intent,"Share encrypted file"));resolve(invoke)
                        } catch (_:Exception) {reject(invoke,"This document provider could not share the file.")}
                    }}
                })
            };return
        }
        if(command=="android_scan_code") {
            requestPermissionForAlias("camera",invoke,"scanGranted");return
        }
        if(command=="android_wifi_permission") {
            requestPermissionForAlias("wifi",invoke,"wifiGranted");return
        }
        if(command=="android_background_wifi_settings") {
            activity.startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,android.net.Uri.parse("package:${activity.packageName}")));resolve(invoke);return
        }
        if(command=="android_location_settings") {
            activity.startActivity(Intent(Settings.ACTION_LOCATION_SOURCE_SETTINGS));resolve(invoke);return
        }
        if (command == "install_release_update" && args.optJSONObject("input")?.optBoolean("baseline_only")!=true && !activity.packageManager.canRequestPackageInstalls()) {
            activity.startActivity(Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,android.net.Uri.parse("package:${activity.packageName}")))
            reject(invoke,"Allow SirinVPN to request Android package installation, then retry the reviewed update.");return
        }
        if (command == "android_choose_applications") {
            val previous = args.optJSONObject("selection")
            val packages = activity.packageManager.getInstalledApplications(0).filter { it.packageName != activity.packageName && it.enabled }
                .sortedBy { activity.packageManager.getApplicationLabel(it).toString().lowercase() }
            val selected = BooleanArray(packages.size) { i -> previous?.optJSONArray("packages")?.let { values -> (0 until values.length()).any { values.getString(it) == packages[i].packageName } } == true }
            android.app.AlertDialog.Builder(activity).setTitle("Application routing")
                .setItems(arrayOf("Only selected applications use VPN","Selected applications bypass VPN")) { _,mode ->
                    val dialog = android.app.AlertDialog.Builder(activity).setTitle(if (mode==0) "Use VPN" else "Bypass VPN")
                        .setMultiChoiceItems(packages.map { "${activity.packageManager.getApplicationLabel(it)}\n${it.packageName}" }.toTypedArray(),selected) { _,which,checked -> selected[which]=checked }
                        .setPositiveButton("Use selection") { _,_ -> resolve(invoke,JSONObject().put("mode",if(mode==0) "include" else "exclude")
                            .put("packages",org.json.JSONArray(packages.filterIndexed { i,_ -> selected[i] }.map { it.packageName }))) }
                        .setNegativeButton("Cancel") { _,_ -> resolve(invoke) }.create()
                    dialog.setOnCancelListener { resolve(invoke) }; dialog.show()
                }.setOnCancelListener { resolve(invoke) }.show()
            return
        }
        if (command in setOf("remember_secret","reveal_secret","secret_qr")) { reject(invoke,"Native-only operation"); return }
        if (command == "android_show_secret" || command == "android_copy_secret") {
            attach()
            link!!.ready.whenComplete { control,error ->
                if (error != null) { reject(invoke,"Protected value unavailable"); return@whenComplete }
                control.execute("reveal_secret",JSONObject().put("reference",args.getString("reference")).toString(),UUID.randomUUID().toString(),-1,object:IResult.Stub(){
                    override fun complete(result:String) {
                        val response=JSONObject(result)
                        activity.runOnUiThread {
                            if (response.has("error")) reject(invoke,"Protected value expired")
                            else { ProtectedValue.show(activity,response.getJSONObject("ok"),command == "android_copy_secret"); resolve(invoke) }
                        }
                    }
                })
            }; return
        }
        if (command == "android_secret_input") {
            val field = android.widget.EditText(activity).apply {
                inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
                importantForAutofill = android.view.View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
                filters = arrayOf(android.text.InputFilter.LengthFilter(131072))
            }
            val dialog = android.app.AlertDialog.Builder(activity).setTitle(args.optString("label","Protected value"))
                .setView(field).setPositiveButton("Use value",null).setNegativeButton("Cancel") { _,_ -> reject(invoke,"Cancelled") }
                .setNeutralButton("Clear value") { _,_ -> field.text?.clear();resolve(invoke,"") }.create()
            dialog.setOnCancelListener { reject(invoke,"Cancelled") }
            dialog.setOnDismissListener {field.text?.clear()}
            dialog.window?.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
            dialog.show()
            dialog.getButton(android.app.AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val minimum=args.optInt("minimumLength",0).coerceIn(0,1024)
                if(field.text.length<minimum) field.error="Use at least $minimum characters."
                else {send(invoke,"remember_secret",JSONObject().put("value",field.text.toString()));field.text?.clear();dialog.dismiss()}
            }
            return
        }
        if (command == "android_confirm") {
            val dialog = android.app.AlertDialog.Builder(activity).setTitle("SirinVPN")
                .setMessage(args.getString("message")).setPositiveButton("Confirm") { _,_ -> resolve(invoke,true) }
                .setNegativeButton("Cancel") { _,_ -> resolve(invoke,false) }.create()
            dialog.setOnCancelListener { resolve(invoke,false) }; dialog.show(); return
        }
        if (command == "android_open_document" || command == "android_save_document") {
            val save = command == "android_save_document"
            val intent = Intent(if (save) Intent.ACTION_CREATE_DOCUMENT else Intent.ACTION_OPEN_DOCUMENT)
                .addCategory(Intent.CATEGORY_OPENABLE).setType("application/octet-stream")
            if (save) intent.putExtra(Intent.EXTRA_TITLE,args.optJSONObject("options")?.optString("defaultPath")?.substringAfterLast('/') ?: "SirinVPN.sirinbackup")
            startActivityForResult(invoke,intent,"documentSelected"); return
        }
        if (command == "register_status") { registerListener(invoke); return }
        if (command == "client_platform") { resolve(invoke, "android"); return }
        if (command == "get_app_preferences") { resolve(invoke, appPreferences()); return }
        if (command == "set_app_preferences") {
            val prefs = args.getJSONObject("preferences")
            activity.getSharedPreferences("presentation",0).edit().putBoolean("animations",prefs.getBoolean("animations"))
                .putBoolean("notifications",prefs.getBoolean("notifications")).apply()
            resolve(invoke, appPreferences()); return
        }
        if (command == "android_vpn_settings") { activity.startActivity(Intent(Settings.ACTION_VPN_SETTINGS)); resolve(invoke); return }
        if (command == "android_notification_settings") {
            activity.startActivity(Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE,activity.packageName))
            resolve(invoke); return
        }
        if (command == "request_notification_permission" || command == "test_notification") {
            if (Build.VERSION.SDK_INT >= 33 && activity.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                activity.getSharedPreferences("presentation",0).edit().putBoolean("notification_permission_requested",true).apply()
                requestPermissionForAlias("notifications",invoke,"notificationsGranted");return
            }
            if (command == "test_notification") testNotification(invoke) else resolve(invoke, notificationPermission())
            return
        }
        if (command == "android_add_tile") {
            if (Build.VERSION.SDK_INT >= 33) activity.getSystemService(StatusBarManager::class.java).requestAddTileService(
                ComponentName(activity,SirinTileService::class.java),"SirinVPN",Icon.createWithResource(activity,R.drawable.ic_sirin_vpn),activity.mainExecutor
            ) { resolve(invoke,it) }
            else { resolve(invoke,"Open Quick Settings, tap Edit and drag SirinVPN into the active tiles.") }
            return
        }
        if (command == "android_snapshot") {
            attach(); link!!.ready.whenComplete { control,error ->
                if (error != null) reject(invoke,"The service is unavailable") else resolve(invoke,JSONObject(control.snapshot()))
            }; return
        }
        val startsVpn = command in setOf("connect_server","connect_server_with_policy","connect_saved","resume_server","reconnect_server","join_server","recover_owner_access") || command=="set_wifi_policy" && args.optJSONObject("policy")?.optBoolean("enabled")==true
        if (startsVpn || command in setOf("rotate_device_keys","apply_endpoint_update","publish_endpoint_update")) {
            val preferences=activity.getSharedPreferences("presentation",0)
            if (startsVpn && Build.VERSION.SDK_INT>=33 && notificationPermission()!="granted" && !preferences.getBoolean("notification_permission_requested",false)) {
                // Ask once in context; denial must never prevent connecting the VPN.
                preferences.edit().putBoolean("notification_permission_requested",true).apply()
                requestPermissionForAlias("notifications",invoke,"connectionNotificationsGranted");return
            }
            prepareVpnCommand(invoke);return
        }
        send(invoke, command, args)
    }
    private fun prepareVpnCommand(invoke:Invoke) {
        val consent=VpnService.prepare(activity)
        if(consent!=null) startActivityForResult(invoke,consent,"vpnConsent")
        else {val request=invoke.getArgs();send(invoke,request.getString("command")!!,request.optJSONObject("args") ?: JSONObject())}
    }
    @PermissionCallback private fun connectionNotificationsGranted(invoke:Invoke) { prepareVpnCommand(invoke) }
    @PermissionCallback private fun wifiGranted(invoke:Invoke) {
        resolve(invoke,activity.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION)==PackageManager.PERMISSION_GRANTED)
    }
    @PermissionCallback private fun notificationsGranted(invoke:Invoke) {
        if(invoke.getArgs().getString("command")=="test_notification") testNotification(invoke)
        else resolve(invoke,notificationPermission())
    }
    private fun testNotification(invoke:Invoke) {
        if(notificationPermission()!="granted") {reject(invoke,"Notifications are blocked. Allow SirinVPN in Android notification settings.");return}
        VpnNotifications.channels(activity)
        activity.getSystemService(NotificationManager::class.java).notify(71,
            android.app.Notification.Builder(activity,VpnNotifications.CHANNEL).setSmallIcon(R.drawable.ic_sirin_vpn)
                .setBadgeIconType(android.app.Notification.BADGE_ICON_NONE)
                .setContentTitle("SirinVPN").setContentText("Android notifications are available.").setAutoCancel(true)
                .setContentIntent(VpnNotifications.openApp(activity)).build())
        resolve(invoke)
    }
    @PermissionCallback private fun scanGranted(invoke:Invoke) {
        if(activity.checkSelfPermission(Manifest.permission.CAMERA)!=PackageManager.PERMISSION_GRANTED) {reject(invoke,"Camera permission was not granted. You can enter the code securely instead.");return}
        if (scanner != null) { reject(invoke,"A scanner is already open."); return }
        scanner = CodeScanner(activity) { value ->
            scanner = null
            if (value == null) reject(invoke,"Scanning cancelled. You can enter the code securely instead.")
            else if (value.length > 131072) reject(invoke,"Code is too large")
            else send(invoke,"remember_secret",JSONObject().put("value",value))
        }.also { it.show() }
    }
    @ActivityCallback private fun vpnConsent(invoke: Invoke, result: ActivityResult) {
        if (result.resultCode != Activity.RESULT_OK) { reject(invoke,"VPN permission was not granted."); return }
        val request = invoke.getArgs()
        send(invoke,request.getString("command")!!,request.optJSONObject("args") ?: JSONObject())
    }
    @ActivityCallback private fun documentSelected(invoke: Invoke, result: ActivityResult) {
        val uri = result.data?.data
        if (result.resultCode != Activity.RESULT_OK || uri == null) { resolve(invoke); return }
        val flags = (result.data?.flags ?: 0) and (Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
        try {
            if (flags and Intent.FLAG_GRANT_READ_URI_PERMISSION != 0) activity.contentResolver.takePersistableUriPermission(uri,Intent.FLAG_GRANT_READ_URI_PERMISSION)
            if (flags and Intent.FLAG_GRANT_WRITE_URI_PERMISSION != 0) activity.contentResolver.takePersistableUriPermission(uri,Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
        } catch (_: SecurityException) {}
        resolve(invoke,uri.toString())
    }
    private fun send(invoke: Invoke, command: String, args: JSONObject) {
        attach()
        link!!.ready.whenComplete { control,error ->
            if (error != null) { reject(invoke,"The Android service is unavailable."); return@whenComplete }
            try {
                val expected = if (command in setOf("disconnect_server","cancel_connection","reconnect_server")) JSONObject(control.snapshot()).getLong("generation") else -1L
                control.execute(command,args.toString(),UUID.randomUUID().toString(),expected,object : IResult.Stub() {
                    override fun complete(result: String) { invoke.resolve(JSObject(result)) }
                })
            } catch (_: Exception) { reject(invoke,"The service connection was interrupted.") }
        }
    }
    // Expected, reviewed user-facing errors share the service response envelope.
    // Plugin transport rejection is reserved for an unavailable bridge.
    private fun reject(invoke: Invoke, message: String) { invoke.resolve(JSObject().put("error",message)) }
    private fun resolve(invoke: Invoke, value: Any = JSONObject.NULL) { invoke.resolve(JSObject().put("ok",value)) }
    private fun notificationPermission(): String = if (activity.getSystemService(NotificationManager::class.java).areNotificationsEnabled()) "granted" else "denied"
    private fun appPreferences(): JSONObject {
        val prefs = activity.getSharedPreferences("presentation",0)
        return JSONObject().put("preferences",JSONObject().put("start_on_login",false).put("launch_minimized",false)
            .put("close_to_tray",false).put("notifications",prefs.getBoolean("notifications",true)).put("animations",prefs.getBoolean("animations",true)))
            .put("startup_available",false).put("tray_available",false).put("notification_permission",notificationPermission())
            .put("font_scale",activity.resources.configuration.fontScale)
    }
}
