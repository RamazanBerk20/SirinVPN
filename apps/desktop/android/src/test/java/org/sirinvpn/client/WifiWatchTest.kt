package org.sirinvpn.client

import org.junit.Assert.*
import org.junit.Test
import org.sirinvpn.client.WifiRule.Watch
import org.sirinvpn.client.WifiWatch.Step

class WifiWatchTest {
    @Test fun aProcessStartReappliesTheJoinCallbackFromItsSavedNumber() {
        // The previous process may have left callback 5 registered: cancel it whatever the rule wants.
        assertEquals(Step(WifiWatch.None, cancelJoin = 5), WifiWatch.arm(null, Watch.NONE, 5))
        assertEquals(Step(WifiWatch.JoinCallback(6), cancelJoin = 5, registerJoin = 6), WifiWatch.arm(null, Watch.WIFI_JOIN, 5))
        assertEquals(Step(WifiWatch.None, cancelJoin = 5, monitor = true), WifiWatch.arm(null, Watch.MONITOR, 5))
    }

    @Test fun anArmedCallbackStaysUntilDeliveredThenTheNextArmingUsesANewNumber() {
        val armed = WifiWatch.JoinCallback(6)
        assertEquals(Step(armed), WifiWatch.arm(armed, Watch.WIFI_JOIN, 6))
        val delivered = WifiWatch.joinDelivered(armed)
        assertEquals(WifiWatch.None, delivered)
        assertEquals(Step(WifiWatch.JoinCallback(7), cancelJoin = 6, registerJoin = 7), WifiWatch.arm(delivered, Watch.WIFI_JOIN, 6))
    }

    @Test fun joiningWifiSwapsTheCallbackForTheMonitorOnlyOnceItRuns() {
        val start = WifiWatch.arm(WifiWatch.JoinCallback(6), Watch.MONITOR, 6)
        assertEquals(Step(WifiWatch.None, cancelJoin = 6, monitor = true), start)
        // A refused background start is retried by the next check.
        assertEquals(Step(WifiWatch.None, monitor = true), WifiWatch.arm(start.next, Watch.MONITOR, 6))
        val running = WifiWatch.monitorStarted(start.next, 6)
        assertEquals(Step(WifiWatch.Monitor), running)
        assertEquals(Step(WifiWatch.Monitor), WifiWatch.arm(running.next, Watch.MONITOR, 6))
    }

    @Test fun leavingWifiStopsTheMonitorAndArmsTheCallback() {
        assertEquals(Step(WifiWatch.JoinCallback(7), cancelJoin = 6, registerJoin = 7, monitor = false),
            WifiWatch.arm(WifiWatch.Monitor, Watch.WIFI_JOIN, 6))
        assertEquals(Step(WifiWatch.None, monitor = false), WifiWatch.arm(WifiWatch.Monitor, Watch.NONE, 6))
        // The service's own stop report never undoes a newer callback.
        assertEquals(WifiWatch.JoinCallback(7), WifiWatch.monitorStopped(WifiWatch.JoinCallback(7)))
        assertEquals(WifiWatch.None, WifiWatch.monitorStopped(WifiWatch.Monitor))
    }

    @Test fun aMonitorThatStartsBeforeTheFirstCheckCancelsTheSavedCallback() {
        assertEquals(Step(WifiWatch.Monitor, cancelJoin = 5), WifiWatch.monitorStarted(null, 5))
        assertEquals(Step(WifiWatch.Monitor, cancelJoin = 6), WifiWatch.monitorStarted(WifiWatch.JoinCallback(6), 6))
        assertEquals(WifiWatch.Monitor, WifiWatch.joinDelivered(WifiWatch.Monitor))
    }

    @Test fun nothingWantedAndNothingArmedDoesNothing() {
        assertEquals(Step(WifiWatch.None), WifiWatch.arm(WifiWatch.None, Watch.NONE, 6))
    }
}
