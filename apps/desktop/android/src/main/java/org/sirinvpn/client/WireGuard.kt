package org.sirinvpn.client

object WireGuard {
    init { System.loadLibrary("sirin_wireguard") }
    external fun start(fd: Int, configuration: String): Int
    external fun stop(handle: Int)
    external fun commit(handle: Int): Boolean
    external fun socket4(handle: Int): Int
    external fun socket6(handle: Int): Int
    /** Returns only counters and handshake age, never the UAPI containing private keys. */
    external fun statistics(handle: Int): LongArray?
    external fun probeStart(configuration:String):Int
    external fun probeSample(handle:Int,source:String,destination:String):LongArray?
    external fun endpoint(handle:Int,configuration:String):Boolean
}
