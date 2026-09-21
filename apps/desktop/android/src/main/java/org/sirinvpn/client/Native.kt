package org.sirinvpn.client

/** Loaded by :vpn independently; never initializes Tauri or a WebView. */
object Native {
    init { System.loadLibrary("sirinvpn_android_runtime") }
    external fun initialize(directory: String, platform: NativePlatform): Boolean
    external fun call(command: String, arguments: String, generation: Long): String
    external fun stopTransport()
    external fun generation(value:Long)
}
