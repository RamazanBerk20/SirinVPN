package org.sirinvpn.client

import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat

class MainActivity : TauriActivity() {
    private var appWebView:android.webkit.WebView?=null
    override fun onWebViewCreate(webView:android.webkit.WebView) {
        super.onWebViewCreate(webView)
        appWebView=webView
        webView.settings.textZoom=(resources.configuration.fontScale*100).toInt().coerceIn(50,300)
    }
    override fun onConfigurationChanged(configuration:android.content.res.Configuration) {
        super.onConfigurationChanged(configuration)
        appWebView?.settings?.textZoom=(configuration.fontScale*100).toInt().coerceIn(50,300)
        val size=if(configuration.fontScale>=1.5f) "large" else "normal"
        appWebView?.evaluateJavascript("document.documentElement.dataset.fontScale='$size'",null)
    }
    override fun setContentView(view:android.view.View?) {
        // Vite's pinned browser baseline is Chrome 111. Old Android 10 factory
        // images can still ship WebView 74; explain the update instead of a blank UI.
        // Wry installs its WebView asynchronously after onCreate, so intercept
        // that installation rather than displaying a notice it would overwrite.
        val provider=android.webkit.WebView.getCurrentWebViewPackage()
        val major=provider?.versionName?.substringBefore('.')?.toIntOrNull() ?: 0
        if(view is android.webkit.WebView && major<111) {
            val content=android.widget.LinearLayout(this).apply {
                orientation=android.widget.LinearLayout.VERTICAL
                val padding=(24*resources.displayMetrics.density).toInt()
                setPadding(padding,padding,padding,padding)
                addView(android.widget.TextView(this@MainActivity).apply {
                    text="Update Android System WebView\n\nSirinVPN needs WebView 111 or newer. Update the system WebView, then reopen SirinVPN."
                    textSize=20f
                })
                addView(android.widget.Button(this@MainActivity).apply {
                    text="Open WebView settings"
                    setOnClickListener { startActivity(android.content.Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                        android.net.Uri.parse("package:${provider?.packageName ?: "com.google.android.webview"}"))) }
                })
            }
            super.setContentView(android.widget.ScrollView(this).apply {addView(content)})
            return
        }
        super.setContentView(view)
    }
    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        // The generated Tauri class defines this observer but does not attach it.
        // Use the Activity lifecycle so native plugins release the camera on Home.
        lifecycle.addObserver(TauriLifecycleObserver)
        // Insets are consumed once at the native boundary, including the IME.
        val root = findViewById<android.view.View>(android.R.id.content)
        ViewCompat.setOnApplyWindowInsetsListener(root) { view, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout())
            val ime = insets.getInsets(WindowInsetsCompat.Type.ime())
            view.setPadding(bars.left, bars.top, bars.right, maxOf(bars.bottom, ime.bottom))
            WindowInsetsCompat.CONSUMED
        }
    }
}
