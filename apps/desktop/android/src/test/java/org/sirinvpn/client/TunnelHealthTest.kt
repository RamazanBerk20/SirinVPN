package org.sirinvpn.client

import org.junit.Assert.*
import org.junit.Test

class TunnelHealthTest {
    @Test fun receivingTunnelSurvivesAnOldHandshakeAndClockCorrection() {
        val health = TunnelHealth()
        // The last handshake can be arbitrarily old in wall time while authenticated
        // receive counters continue advancing. Elapsed time is the only deadline.
        for (now in 0L..600000L step 1000) assertTrue(health.record(now, now / 1000, 1))
        assertTrue(health.record(601000, 600, 1))
        assertTrue(health.record(602000, 601, 0))
    }

    @Test fun continuousSilenceRequiresTheFullWindowAndProgressRecoversIt() {
        val health = TunnelHealth()
        for (now in 0L until 180000L step 1000) assertTrue(health.record(now, 20, 1))
        assertFalse(health.record(180000, 20, 1))
        assertTrue("Authenticated traffic recovers without reconnecting", health.record(181000, 21, 1))
        for (now in 182000L until 361000L step 1000) assertTrue(health.record(now, 21, 1))
        assertTrue("A new handshake is also authenticated progress", health.record(361000, 21, 2))
    }

    @Test fun sleepSamplerGapsAndCounterResetsDiscardOldFailureEvidence() {
        for (reset in listOf("sleep", "clock", "counter")) {
            val health = TunnelHealth()
            for (now in 0L..180000L step 1000) health.record(now, 100, 1)
            assertFalse(health.record(181000, 100, 1))
            val at = when (reset) { "sleep" -> 220000L; "clock" -> 1000L; else -> 182000L }
            val rx = if (reset == "counter") 0L else 100L
            assertTrue(reset, health.record(at, rx, 1))
            for (now in at + 1000 until at + 180000 step 1000) assertTrue(reset, health.record(now, rx, 1))
            assertFalse(reset, health.record(at + 180000, rx, 1))
        }
    }
}
