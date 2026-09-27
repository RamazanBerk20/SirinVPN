package org.sirinvpn.client

import android.app.Activity
import android.app.Dialog
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.Rect
import android.os.Bundle
import android.view.Gravity
import android.view.WindowManager
import android.widget.Button
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.TextView
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.NotFoundException
import com.google.zxing.Result
import com.google.zxing.multi.qrcode.QRCodeMultiReader
import com.journeyapps.barcodescanner.*
import com.journeyapps.barcodescanner.camera.FitCenterStrategy

/** Decode the entire visible preview. The old unmarked centre crop cut off dense QR codes. */
internal class QrCameraView(context: android.content.Context) : BarcodeView(context) {
    override fun calculateFramingRect(container: Rect, surface: Rect) = Rect(container).apply {
        if (!intersect(surface)) setEmpty()
    }

    init {
        decoderFactory = DecoderFactory { baseHints ->
            // Dense codes contain finder-like patterns. Examine all plausible triples;
            // the single-code detector can choose a false triple and miss a valid code.
            MixedDecoder(object : com.google.zxing.Reader {
                private val reader = QRCodeMultiReader()
                override fun decode(image: BinaryBitmap): Result = decode(image, baseHints)
                override fun decode(image: BinaryBitmap, hints: MutableMap<DecodeHintType, *>?): Result =
                    reader.decodeMultiple(image, (hints ?: emptyMap()) + (DecodeHintType.TRY_HARDER to true)).firstOrNull()
                        ?: throw NotFoundException.getNotFoundInstance()
                override fun reset() { reader.reset() }
            })
        }
        cameraSettings.isContinuousFocusEnabled = true
        previewScalingStrategy = object : FitCenterStrategy() {
            override fun getBestPreviewSize(sizes: MutableList<Size>, desired: Size?): Size {
                // Dense invitation codes need camera pixels even on a small logical display.
                val hd = sizes.filter { minOf(it.width, it.height) >= 720 && it.width * it.height <= 1920 * 1080 }
                return super.getBestPreviewSize(if (hd.isEmpty()) sizes else hd.toMutableList(), desired)
            }
        }
    }
}

/** A native window keeps the camera and decoded secret out of the WebView and Intents. */
internal class CodeScanner(private val activity: Activity, private val result: (String?) -> Unit) :
    Dialog(activity, android.R.style.Theme_Material_NoActionBar) {
    private val camera = QrCameraView(activity)
    private var completed = false

    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE or WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        val density = activity.resources.displayMetrics.density
        fun dp(value: Int) = (value * density).toInt()
        val root = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.rgb(7, 16, 31))
        }
        ViewCompat.setOnApplyWindowInsetsListener(root) { view, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout())
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            insets
        }
        val header = LinearLayout(activity).apply { gravity = Gravity.CENTER_VERTICAL; setPadding(dp(12), dp(8), dp(12), 0) }
        header.addView(Button(activity).apply { text = "Back"; minHeight = dp(48); setOnClickListener { dismiss() } })
        header.addView(TextView(activity).apply { text = "Scan QR code"; textSize = 21f; setPadding(dp(12), 0, 0, 0) }, LinearLayout.LayoutParams(0, -2, 1f))
        root.addView(header)
        val guidance = TextView(activity).apply {
            text = "Keep the whole code visible. For a dense code, enlarge it on the other screen and hold steady."
            textSize = 16f; setTextColor(Color.rgb(177, 194, 220)); setPadding(dp(20), dp(16), dp(20), dp(16))
            accessibilityLiveRegion = android.view.View.ACCESSIBILITY_LIVE_REGION_POLITE
        }
        root.addView(guidance)
        val preview = FrameLayout(activity)
        preview.addView(camera, FrameLayout.LayoutParams(-1, -1))
        preview.addView(ViewfinderView(activity, null).apply { setCameraPreview(camera) }, FrameLayout.LayoutParams(-1, -1))
        root.addView(preview, LinearLayout.LayoutParams(-1, 0, 1f))
        val controls = LinearLayout(activity).apply { gravity = Gravity.CENTER; setPadding(dp(12), dp(12), dp(12), dp(12)) }
        if (activity.packageManager.hasSystemFeature(PackageManager.FEATURE_CAMERA_FLASH)) {
            controls.addView(Button(activity).apply {
                var on = false
                text = "Flashlight on"; minHeight = dp(48)
                setOnClickListener { on = !on; camera.setTorch(on); text = if (on) "Flashlight off" else "Flashlight on" }
            })
        }
        controls.addView(Button(activity).apply {
            text = "Refocus"; minHeight = dp(48)
            setOnClickListener {
                camera.pause()
                camera.cameraSettings.isContinuousFocusEnabled = !camera.cameraSettings.isContinuousFocusEnabled
                camera.resume()
                guidance.text = "Focus reset. Move a little closer or farther away, keeping the entire code visible."
            }
        })
        root.addView(controls)
        camera.addStateListener(object : CameraPreview.StateListener {
            override fun previewSized() {}
            override fun previewStarted() {}
            override fun previewStopped() {}
            override fun cameraClosed() {}
            override fun cameraError(error: Exception) {
                guidance.text = "Camera unavailable. Tap Refocus to retry, or go back and enter the code securely."
            }
        })
        camera.decodeSingle(object : BarcodeCallback {
            override fun barcodeResult(barcode: BarcodeResult) {
                if (completed) return
                completed = true
                pauseCamera()
                dismiss()
                result(barcode.text)
            }
        })
        setOnDismissListener { pauseCamera(); if (!completed) { completed = true; result(null) } }
        setContentView(root)
        window?.setLayout(-1, -1)
    }

    fun resumeCamera() { if (isShowing && !completed) camera.resume() }
    fun pauseCamera() { camera.pause() }
    override fun onStart() { super.onStart(); camera.resume() }
    override fun onStop() { pauseCamera(); super.onStop() }
}
