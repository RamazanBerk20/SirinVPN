package org.sirinvpn.client

import android.graphics.Color
import android.graphics.Rect
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import com.journeyapps.barcodescanner.Size
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class QrScannerTest {
    @Test fun denseCodesAcrossTheVisiblePreview() {
        assertTrue(BuildConfig.DEBUG)
        assertTrue(android.os.Build.HARDWARE in setOf("ranchu", "goldfish"))
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        instrumentation.runOnMainSync {
                val camera = QrCameraView(instrumentation.targetContext)
                val framing = QrCameraView::class.java.getDeclaredMethod("calculateFramingRect", Rect::class.java, Rect::class.java).apply { isAccessible = true }
                val frame = framing.invoke(camera, Rect(0, 0, 1080, 1920), Rect(0, 0, 1080, 1920)) as Rect
                assertEquals(Rect(0, 0, 1080, 1920), frame)
                assertTrue(camera.cameraSettings.isContinuousFocusEnabled)
                val size = camera.previewScalingStrategy.getBestPreviewSize(mutableListOf(Size(640, 480), Size(1920, 1080)), Size(320, 480))
                assertEquals(Size(1920, 1080), size)
                // Deterministic synthetic data near QR capacity; never a usable invitation.
                val random = java.util.Random(37)
                val alphabet = "abcdefghijklmnopqrstuvwxyz0123456789-_"
                val value = "sirin1." + (1..2400).map { alphabet[random.nextInt(alphabet.length)] }.joinToString("")
                val qr = QRCodeWriter().encode(value, BarcodeFormat.QR_CODE, 960, 960, mapOf(EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.L))
                for (inverted in listOf(false, true)) {
                    val pixels = IntArray(1080 * 1920) { if (inverted) Color.BLACK else Color.WHITE }
                    // The old invisible 10% centre crop excludes the finder patterns here.
                    for (y in 0 until qr.height) for (x in 0 until qr.width)
                        pixels[(y + 120) * 1080 + x + 8] = if (qr[x, y] != inverted) Color.BLACK else Color.WHITE
                    val source = RGBLuminanceSource(1080, 1920, pixels).crop(frame.left, frame.top, frame.width(), frame.height())
                    val decoder = camera.decoderFactory.createDecoder(emptyMap<com.google.zxing.DecodeHintType, Any>())
                    val decoded = decoder.decode(source) ?: decoder.decode(source)
                    assertNotNull("Dense QR at preview edge must decode in either polarity", decoded)
                    assertEquals(value, decoded.text)
                }
        }
    }
}
