package org.sirinvpn.client

import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.view.WindowManager
import android.widget.TextView
import android.widget.ScrollView

/** Secret presentation and deliberate sharing stay outside the WebView. */
object ProtectedValue {
    private fun copy(activity: Activity, value: String) {
        val clipboard = activity.getSystemService(ClipboardManager::class.java)
        val clip = ClipData.newPlainText("SirinVPN protected value",value)
        clip.description.extras = PersistableBundle().apply { putBoolean("android.content.extra.IS_SENSITIVE",true) }
        clipboard.setPrimaryClip(clip)
        Handler(Looper.getMainLooper()).postDelayed({
            if (clipboard.primaryClip?.getItemAt(0)?.text?.toString() == value) clipboard.clearPrimaryClip()
        },60000)
    }
    fun show(activity: Activity,material: org.json.JSONObject,copyOnly: Boolean) {
        val value=material.getString("value")
        if (copyOnly) { copy(activity,value); return }
        val text = TextView(activity).apply {
            this.text = value; textSize = 16f; setPadding(24,24,24,24)
            importantForAutofill = android.view.View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
            setTextIsSelectable(false)
        }
        val content=android.widget.LinearLayout(activity).apply { orientation=android.widget.LinearLayout.VERTICAL }
        material.optJSONArray("qr")?.let { rows ->
            val size=rows.length();require(size in 21..177)
            val bitmap=android.graphics.Bitmap.createBitmap(size+8,size+8,android.graphics.Bitmap.Config.ARGB_8888)
            bitmap.eraseColor(android.graphics.Color.WHITE)
            for(y in 0 until size) { val row=rows.getString(y);require(row.length==size)
                for(x in 0 until size) if(row[x]=='1') bitmap.setPixel(x+4,y+4,android.graphics.Color.BLACK)
            }
            content.addView(android.widget.ImageView(activity).apply {
                setImageBitmap(bitmap);adjustViewBounds=true;minimumHeight=280
                contentDescription="Protected QR code"
                (drawable as? android.graphics.drawable.BitmapDrawable)?.isFilterBitmap=false
            })
        }
        content.addView(text)
        val dialog = AlertDialog.Builder(activity).setTitle("Protected SirinVPN value")
            .setView(ScrollView(activity).apply { addView(content) })
            .setPositiveButton("Close") { _,_ -> text.text = "" }
            .setNegativeButton("Copy for 1 minute") { _,_ -> copy(activity,value); text.text = "" }
            .create()
        dialog.window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        dialog.setOnDismissListener { text.text = "" }
        dialog.show()
    }
}
