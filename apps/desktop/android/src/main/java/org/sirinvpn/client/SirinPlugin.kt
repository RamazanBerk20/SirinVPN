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
import android.os.IBinder
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

@TauriPlugin(permissions=[Permission(alias="camera",strings=[Manifest.permission.CAMERA]),Permission(alias="notifications",strings=[Manifest.permission.POST_NOTIFICATIONS])])
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
        if(command=="android_system_bars") {val light=args.optBoolean("light");activity.runOnUiThread {(activity as? MainActivity)?.systemBars(light)};resolve(invoke);return}
        if(command=="android_share_document") {
            val uri=android.net.Uri.parse(args.optString("uri"))
            if(uri.scheme!="content") {reject(invoke,R.string.error_choose_document);return}
            attach()
            link!!.ready.whenComplete {control,error ->
                if(error!=null) reject(invoke,R.string.error_service_unavailable)
                else execute(control,"authorize_document_share",args.toString(),-1,{reject(invoke,R.string.error_service_interrupted)}) {result -> activity.runOnUiThread {
                    if(JSONObject(result).has("error")) reject(invoke,R.string.error_share_expired)
                    else try {
                        val intent=Intent(Intent.ACTION_SEND).setType("application/octet-stream").putExtra(Intent.EXTRA_STREAM,uri)
                            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                        intent.clipData=android.content.ClipData.newRawUri(activity.getString(R.string.share_clip_label),uri)
                        activity.startActivity(Intent.createChooser(intent,activity.getString(R.string.share_chooser_title)));resolve(invoke)
                    } catch (_:Exception) {reject(invoke,R.string.error_share_failed)}
                }}
            };return
        }
        if(command=="android_scan_code") {
            requestPermissionForAlias("camera",invoke,"scanGranted");return
        }
        if (command == "install_release_update" && args.optJSONObject("input")?.optBoolean("baseline_only")!=true && !activity.packageManager.canRequestPackageInstalls()) {
            activity.startActivity(Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,android.net.Uri.parse("package:${activity.packageName}")))
            reject(invoke,R.string.error_install_permission);return
        }
        if (command == "android_choose_applications") {
            val previous = args.optJSONObject("selection")
            val packages = activity.packageManager.getInstalledApplications(0).filter { it.packageName != activity.packageName && it.enabled }
                .sortedBy { activity.packageManager.getApplicationLabel(it).toString().lowercase() }
            val selected = BooleanArray(packages.size) { i -> previous?.optJSONArray("packages")?.let { values -> (0 until values.length()).any { values.getString(it) == packages[i].packageName } } == true }
            android.app.AlertDialog.Builder(activity).setTitle(R.string.routing_title)
                .setItems(arrayOf(activity.getString(R.string.routing_mode_include),activity.getString(R.string.routing_mode_exclude))) { _,mode ->
                    val dialog = android.app.AlertDialog.Builder(activity).setTitle(if (mode==0) R.string.routing_include_title else R.string.routing_exclude_title)
                        .setMultiChoiceItems(packages.map { activity.getString(R.string.routing_app_row,activity.packageManager.getApplicationLabel(it),it.packageName) }.toTypedArray(),selected) { _,which,checked -> selected[which]=checked }
                        .setPositiveButton(R.string.routing_use_selection) { _,_ -> resolve(invoke,JSONObject().put("mode",if(mode==0) "include" else "exclude")
                            .put("packages",org.json.JSONArray(packages.filterIndexed { i,_ -> selected[i] }.map { it.packageName }))) }
                        .setNegativeButton(R.string.dialog_cancel) { _,_ -> resolve(invoke) }.create()
                    dialog.setOnCancelListener { resolve(invoke) }; dialog.show()
                }.setOnCancelListener { resolve(invoke) }.show()
            return
        }
        if (command in setOf("remember_secret","reveal_secret","secret_qr")) { reject(invoke,"Native-only operation"); return }
        if (command == "android_show_secret" || command == "android_copy_secret") {
            attach()
            link!!.ready.whenComplete { control,error ->
                if (error != null) { reject(invoke,R.string.error_protected_value_unavailable); return@whenComplete }
                execute(control,"reveal_secret",JSONObject().put("reference",args.getString("reference")).toString(),-1,{reject(invoke,R.string.error_protected_value_unavailable)}) { result ->
                    val response=JSONObject(result)
                    activity.runOnUiThread {
                        if (response.has("error")) reject(invoke,R.string.error_protected_value_expired)
                        else { ProtectedValue.show(activity,response.getJSONObject("ok"),command == "android_copy_secret"); resolve(invoke) }
                    }
                }
            }; return
        }
        if (command == "android_secret_input") {
            val field = android.widget.EditText(activity).apply {
                inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
                importantForAutofill = android.view.View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
                filters = arrayOf(android.text.InputFilter.LengthFilter(131072))
            }
            val dialog = android.app.AlertDialog.Builder(activity).setTitle(args.optString("label",activity.getString(R.string.protected_value_title)))
                .setView(field).setPositiveButton(R.string.secret_input_use,null).setNegativeButton(R.string.dialog_cancel) { _,_ -> reject(invoke,R.string.error_entry_cancelled) }
                .setNeutralButton(R.string.secret_input_clear) { _,_ -> field.text?.clear();resolve(invoke,"") }.create()
            dialog.setOnCancelListener { reject(invoke,R.string.error_entry_cancelled) }
            dialog.setOnDismissListener {field.text?.clear()}
            dialog.window?.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
            dialog.show()
            dialog.getButton(android.app.AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val minimum=args.optInt("minimumLength",0).coerceIn(0,1024)
                if(field.text.length<minimum) field.error=activity.resources.getQuantityString(R.plurals.secret_input_minimum_length,minimum,minimum)
                else {send(invoke,"remember_secret",JSONObject().put("value",field.text.toString()));field.text?.clear();dialog.dismiss()}
            }
            return
        }
        if (command == "android_confirm") {
            val dialog = android.app.AlertDialog.Builder(activity).setTitle(R.string.app_name)
                .setMessage(args.getString("message")).setPositiveButton(R.string.dialog_confirm) { _,_ -> resolve(invoke,true) }
                .setNegativeButton(R.string.dialog_cancel) { _,_ -> resolve(invoke,false) }.create()
            dialog.setOnCancelListener { resolve(invoke,false) }; dialog.show(); return
        }
        if (command == "android_open_document" || command == "android_save_document") {
            val save = command == "android_save_document"
            // A folder is a persisted document tree, used for scheduled VPS backups.
            val intent = if (!save && args.optJSONObject("options")?.optBoolean("directory") == true) Intent(Intent.ACTION_OPEN_DOCUMENT_TREE)
            else Intent(if (save) Intent.ACTION_CREATE_DOCUMENT else Intent.ACTION_OPEN_DOCUMENT)
                .addCategory(Intent.CATEGORY_OPENABLE).setType("application/octet-stream")
            if (save) intent.putExtra(Intent.EXTRA_TITLE,args.optJSONObject("options")?.optString("defaultPath")?.substringAfterLast('/') ?: "SirinVPN.sirinbackup")
            startActivityForResult(invoke,intent,"documentSelected"); return
        }
        if (command == "register_status") { registerListener(invoke); return }
        if (command == "client_platform") { resolve(invoke, "android"); return }
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
                ComponentName(activity,SirinTileService::class.java),activity.getString(R.string.app_name),Icon.createWithResource(activity,R.drawable.ic_sirin_vpn),activity.mainExecutor
            ) { resolve(invoke,it) }
            else { resolve(invoke,activity.getString(R.string.tile_add_instructions)) }
            return
        }
        if (command == "android_snapshot") {
            attach(); link!!.ready.whenComplete { control,error ->
                if (error != null) reject(invoke,R.string.error_service_unavailable) else resolve(invoke,JSONObject(control.snapshot()))
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
    @PermissionCallback private fun notificationsGranted(invoke:Invoke) {
        if(invoke.getArgs().getString("command")=="test_notification") testNotification(invoke)
        else resolve(invoke,notificationPermission())
    }
    private fun testNotification(invoke:Invoke) {
        if(notificationPermission()!="granted") {reject(invoke,R.string.error_notifications_blocked);return}
        VpnNotifications.channels(activity)
        activity.getSystemService(NotificationManager::class.java).notify(71,
            android.app.Notification.Builder(activity,VpnNotifications.CHANNEL).setSmallIcon(R.drawable.ic_sirin_vpn)
                .setBadgeIconType(android.app.Notification.BADGE_ICON_NONE)
                .setContentTitle(activity.getString(R.string.app_name)).setContentText(activity.getString(R.string.notification_test_text)).setAutoCancel(true)
                .setContentIntent(VpnNotifications.openApp(activity)).build())
        resolve(invoke)
    }
    @PermissionCallback private fun scanGranted(invoke:Invoke) {
        if(activity.checkSelfPermission(Manifest.permission.CAMERA)!=PackageManager.PERMISSION_GRANTED) {reject(invoke,R.string.error_camera_denied);return}
        if (scanner != null) { reject(invoke,R.string.error_scanner_open); return }
        scanner = CodeScanner(activity) { value ->
            scanner = null
            if (value == null) reject(invoke,R.string.error_scan_cancelled)
            else if (value.length > 131072) reject(invoke,R.string.error_code_too_large)
            else send(invoke,"remember_secret",JSONObject().put("value",value))
        }.also { it.show() }
    }
    @ActivityCallback private fun vpnConsent(invoke: Invoke, result: ActivityResult) {
        if (result.resultCode != Activity.RESULT_OK) { reject(invoke,R.string.error_vpn_permission_denied); return }
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
            if (error != null) { reject(invoke,R.string.error_service_unavailable); return@whenComplete }
            val expected = try {
                if (command in setOf("disconnect_server","cancel_connection","reconnect_server")) JSONObject(control.snapshot()).getLong("generation") else -1L
            } catch (_: Exception) { reject(invoke,R.string.error_service_interrupted); return@whenComplete }
            execute(control,command,args.toString(),expected,{reject(invoke,R.string.error_service_interrupted)}) { result -> invoke.resolve(JSObject(result)) }
        }
    }
    /**
     * IResult never completes if :vpn dies mid-operation. Settle each request exactly
     * once, from its result or from the service binder's death. Unbinding on pause
     * keeps the callback deliverable, so only process death interrupts a request.
     */
    private fun execute(control: IControl, command: String, args: String, expected: Long, interrupted: () -> Unit, completed: (String) -> Unit) {
        val settled = java.util.concurrent.atomic.AtomicBoolean(false)
        val binder = control.asBinder()
        val death = IBinder.DeathRecipient { if (settled.compareAndSet(false,true)) interrupted() }
        try {
            binder.linkToDeath(death,0)
            control.execute(command,args,UUID.randomUUID().toString(),expected,object : IResult.Stub() {
                override fun complete(result: String) {
                    try { binder.unlinkToDeath(death,0) } catch (_: Exception) {}
                    if (settled.compareAndSet(false,true)) completed(result)
                }
            })
        } catch (_: Exception) {
            try { binder.unlinkToDeath(death,0) } catch (_: Exception) {}
            if (settled.compareAndSet(false,true)) interrupted()
        }
    }
    // Expected, reviewed user-facing errors share the service response envelope.
    // Plugin transport rejection is reserved for an unavailable bridge.
    private fun reject(invoke: Invoke, message: String) { invoke.resolve(JSObject().put("error",message)) }
    private fun reject(invoke: Invoke, @androidx.annotation.StringRes message: Int) = reject(invoke,activity.getString(message))
    private fun resolve(invoke: Invoke, value: Any = JSONObject.NULL) { invoke.resolve(JSObject().put("ok",value)) }
    private fun notificationPermission(): String = if (activity.getSystemService(NotificationManager::class.java).areNotificationsEnabled()) "granted" else "denied"
}
