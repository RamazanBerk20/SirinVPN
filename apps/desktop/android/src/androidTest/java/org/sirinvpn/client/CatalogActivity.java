package org.sirinvpn.client;

/** Separate test APK/UID: no VPN bridge, network client or real profile access. */
public class CatalogActivity extends android.app.Activity {
    @Override public void onCreate(android.os.Bundle state) {
        super.onCreate(state);
        String hardware=android.os.Build.HARDWARE;
        if(!hardware.equals("ranchu") && !hardware.equals("goldfish")) throw new SecurityException("Isolated emulator required");
        android.webkit.WebView.setWebContentsDebuggingEnabled(true);
        android.webkit.WebView web=new android.webkit.WebView(this);
        web.getSettings().setJavaScriptEnabled(true);
        web.getSettings().setDomStorageEnabled(true);
        web.getSettings().setTextZoom((int)(getResources().getConfiguration().fontScale*100));
        web.getSettings().setBlockNetworkLoads(true);
        web.getSettings().setAllowFileAccess(true);
        web.setWebViewClient(new android.webkit.WebViewClient());
        web.setWebChromeClient(new android.webkit.WebChromeClient());
        setContentView(web);
        web.setOnApplyWindowInsetsListener((view,insets)->{
            view.setPadding(insets.getSystemWindowInsetLeft(),insets.getSystemWindowInsetTop(),insets.getSystemWindowInsetRight(),insets.getSystemWindowInsetBottom());
            return insets.consumeSystemWindowInsets();
        });
        web.loadUrl("file:///android_asset/catalog/index.html");
    }
}
