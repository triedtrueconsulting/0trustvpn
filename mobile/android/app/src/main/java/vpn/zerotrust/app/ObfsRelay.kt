package vpn.zerotrust.app

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The client half of the obfuscated transport, in this process.
 *
 * WireGuard has no notion of a pluggable transport, so the only way to wrap
 * it without patching it is to put a UDP socket on loopback and point the
 * tunnel's Endpoint at it. On desktop that socket lives in a separate
 * process; here it cannot, because wireguard-android runs the tunnel inside
 * this app — so it is a pair of threads instead, started before the tunnel
 * comes up and stopped after it goes down.
 *
 * Pure JVM on purpose: no android.* anywhere in this file. That is what lets
 * `tests/emulation/test_obfs.py` compile it and run real packets through the
 * real `0trust-obfs` node binary on a machine with no Android SDK. Without
 * that, a second implementation of a wire format would be shipped having
 * never been executed, and the first time it ran would be on a customer's
 * phone in a country where they needed it to work.
 *
 * ONE THING THIS CLASS CANNOT DO, and the caller must: keep the upstream
 * socket out of the tunnel. Packets this relay sends to the node would
 * otherwise be captured by the VPN's own default route, encrypted by
 * WireGuard, and sent back to this relay — a loop that takes the tunnel down
 * and looks like the network failing. See [AllowedIps.excluding] and its use
 * in [WgConfig].
 */
class ObfsRelay(
    private val serverHost: String,
    private val serverPort: Int,
    pskB64: String,
    /** What the node is to forward to — published by the control plane. */
    private val target: InetSocketAddress,
) {
    private val psk = ObfsCrypto.parseKey(pskB64)
    private val running = AtomicBoolean(false)

    private var down: DatagramSocket? = null   // faces WireGuard, on loopback
    private var up: DatagramSocket? = null     // faces the node
    private var threads = listOf<Thread>()

    @Volatile private var peer: InetSocketAddress? = null

    /** The loopback port WireGuard must use as its Endpoint. */
    @Volatile var localPort: Int = 0
        private set

    /**
     * Bind both sockets and start pumping. Returns the loopback port.
     *
     * The port is allocated here and read back, rather than chosen and hoped
     * for, because the tunnel config that names it is built immediately
     * after and a port collision would otherwise produce a config pointing at
     * nothing.
     */
    @Synchronized
    fun start(): Int {
        check(!running.get()) { "obfs: relay already started" }
        val loopback = InetAddress.getByName("127.0.0.1")
        val d = DatagramSocket(0, loopback)
        val u = DatagramSocket()
        down = d; up = u
        localPort = d.localPort
        running.set(true)

        val server = InetSocketAddress(serverHost, serverPort)
        threads = listOf(
            Thread({ pumpOut(d, u, server) }, "obfs-out").apply { isDaemon = true },
            Thread({ pumpIn(d, u) }, "obfs-in").apply { isDaemon = true },
        )
        threads.forEach { it.start() }
        return localPort
    }

    /** Carry WireGuard's datagrams to the node. */
    private fun pumpOut(d: DatagramSocket, u: DatagramSocket, server: InetSocketAddress) {
        val buf = ByteArray(BUF)
        val p = DatagramPacket(buf, buf.size)
        while (running.get()) {
            try {
                // DatagramPacket.length is both the buffer capacity going
                // in and the received size coming out, and it persists across
                // calls. Resetting it at the top of the loop rather than
                // after a successful send is hygiene, not a fix for a
                // reachable bug: the only send failure here is an oversized
                // datagram, and every packet after one of those is smaller,
                // so nothing was ever actually truncated. It is written this
                // way so that stays true of whatever throws next.
                p.length = buf.size
                d.receive(p)
                peer = InetSocketAddress(p.address, p.port)
                val sealed = ObfsCrypto.pack(psk, target, p.data.copyOf(p.length))
                u.send(DatagramPacket(sealed, sealed.size, server))
            } catch (t: Throwable) {
                if (!running.get()) return
                // Keep going. One malformed or oversized datagram must not
                // end the transport under a live tunnel.
            }
        }
    }

    /** Carry the node's replies back to WireGuard. */
    private fun pumpIn(d: DatagramSocket, u: DatagramSocket) {
        val buf = ByteArray(BUF)
        val p = DatagramPacket(buf, buf.size)
        while (running.get()) {
            try {
                p.length = buf.size            // see pumpOut
                u.receive(p)
                val opened = ObfsCrypto.unpack(psk, p.data, p.length)
                val to = peer
                if (to != null) {
                    d.send(DatagramPacket(opened.payload, opened.payload.size, to))
                }
            } catch (t: Throwable) {
                if (!running.get()) return
                // Dropped in silence and counted nowhere. A public UDP port
                // receives scanner noise continuously, and a log line per
                // unopenable packet is a way to fill a phone's storage.
            }
        }
    }

    /** Stop the relay. Safe to call more than once, and from any thread. */
    @Synchronized
    fun stop() {
        if (!running.getAndSet(false)) return
        // Closing the sockets is what unblocks the receive() calls; the
        // threads then see running == false and return.
        try { down?.close() } catch (_: Throwable) {}
        try { up?.close() } catch (_: Throwable) {}
        threads.forEach { it.join(1_000) }
        threads = emptyList()
        down = null; up = null
        localPort = 0
    }

    val isRunning: Boolean get() = running.get()

    private companion object {
        // A WireGuard packet on a 1500-byte path never approaches this; the
        // slack means a jumbo-frame path does not silently truncate.
        const val BUF = 65535
    }
}

/**
 * The one relay this process may have running.
 *
 * A singleton because the tunnel is: wireguard-android keeps one GoBackend
 * per process, and a second relay would hold a loopback port while carrying
 * nothing. It also has to be reachable from two places that do not share an
 * object — the config is built where Connect is pressed, and the teardown
 * happens in the service — so the alternative to a holder is passing a
 * reference through an Intent, which is not a thing.
 *
 * Still no android.* here, so the interop test can drive this too.
 */
object ObfsRelayHolder {

    @Volatile private var relay: ObfsRelay? = null

    /** The relay's loopback port, or 0 when none is running. */
    val port: Int get() = relay?.takeIf { it.isRunning }?.localPort ?: 0

    val isRunning: Boolean get() = relay?.isRunning == true

    /**
     * Replace whatever was running with a fresh relay and return its
     * loopback port.
     *
     * Always stops the previous one first. A relay from an earlier connect
     * points at whichever node that connect chose, which after a region
     * change or a rotate is not this one — leaving it running would hold a
     * port and send the new tunnel's packets to the old node.
     */
    @Synchronized
    fun restart(serverHost: String, serverPort: Int, pskB64: String,
                target: java.net.InetSocketAddress): Int {
        stop()
        val r = ObfsRelay(serverHost, serverPort, pskB64, target)
        val p = r.start()
        relay = r
        return p
    }

    /** Stop the relay, if there is one. Safe from any thread, any number of times. */
    @Synchronized
    fun stop() {
        relay?.let { try { it.stop() } catch (_: Throwable) {} }
        relay = null
    }
}
