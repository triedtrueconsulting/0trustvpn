package vpn.zerotrust.app

import java.net.Inet4Address
import java.net.InetAddress

/**
 * AllowedIPs arithmetic for the obfuscated transport.
 *
 * THE PROBLEM. With obfuscation on, the tunnel's Endpoint is 127.0.0.1 and a
 * relay in this process forwards the packets to the node. The relay's own
 * upstream socket is an ordinary UDP socket, so the VPN's `0.0.0.0/0` route
 * captures it: WireGuard encrypts the relay's packet, sends it to the
 * Endpoint — which is the relay — which forwards it again. The tunnel dies in
 * a loop that looks like the network being broken.
 *
 * THE FIX. Take the node's address out of the routes the tunnel claims, so
 * packets to it leave on the physical interface. This is the same thing
 * wg-quick does for a peer's endpoint on desktop, expressed the way Android
 * needs it: as the set of prefixes that cover everything EXCEPT one address.
 *
 * WHY THIS FILE IS CAREFUL. The two ways to get it wrong are not symmetric.
 * Cover too little and the node's address stays inside the tunnel: the loop
 * comes back, the tunnel visibly fails, somebody investigates. Cover too much
 * and a slice of the internet quietly stops being routed through the VPN —
 * traffic the customer believes is tunnelled leaves in the clear, with no
 * error anywhere. The second is the one this product cannot ship, so
 * [excluding] is exhaustively tested rather than eyeballed: the result must
 * contain every address except the excluded one, and no address twice.
 *
 * Pure JVM, no android.*, for the same reason as [ObfsCrypto] — so the test
 * can run it.
 */
object AllowedIps {

    /** A CIDR block, as WireGuard writes it. */
    data class Cidr(val address: String, val prefix: Int) {
        override fun toString() = "$address/$prefix"
    }

    /**
     * Every IPv4 prefix that covers `0.0.0.0/0` except [exclude].
     *
     * The construction is the standard complement walk: start at /0 and at
     * each step keep the half that does NOT contain the excluded address,
     * then descend into the half that does. That yields exactly 32 blocks for
     * an IPv4 /32, one per bit, and by construction they are disjoint and
     * their union is everything but the excluded address.
     */
    fun excludingV4(exclude: String): List<Cidr> {
        val target = ipv4ToInt(exclude)
        val out = ArrayList<Cidr>(32)
        for (bit in 0 until 32) {
            val prefixLen = bit + 1
            // FLIP the bit the target takes at this depth, then mask to the
            // prefix. Flipping is the whole operation: an earlier version
            // zeroed the lower bits first and then OR-ed the bit in, which
            // always SET it rather than inverting it — so for any target
            // whose bit was already 1 the "sibling" was the target's own
            // subtree, the excluded address stayed inside the tunnel, and the
            // blocks overlapped each other. It passed for 0.0.0.0 and
            // nothing else, because zero is the one input where setting a
            // bit and flipping it are the same thing.
            val sibling = target xor (1 shl (31 - bit))
            out.add(Cidr(intToIpv4(sibling and maskOf(prefixLen)), prefixLen))
        }
        return out
    }

    /**
     * The AllowedIPs a peer should claim when the relay must reach [nodeIp]
     * outside the tunnel.
     *
     * `::/0` is kept whole and unconditionally, exactly as everywhere else in
     * this product: the tunnel always claims v6 so it cannot leak around us,
     * and without a v6 address on the interface that blackholes it, which is
     * the safe failure. The relay reaches the node over v4; a v6-only node
     * would need the same treatment on the v6 side and is not supported here
     * rather than being half-done — [supportsExclusion] says so.
     */
    fun forRelay(nodeIp: String): List<String> =
        excludingV4(nodeIp).map { it.toString() } + "::/0"

    /**
     * Whether [nodeIp] is an address this can exclude. A v6 node address
     * would need the v6 complement too, which is not implemented — the caller
     * must fall back to a direct tunnel and say so, rather than bringing up
     * an obfuscated one that loops.
     */
    fun supportsExclusion(nodeIp: String): Boolean =
        try {
            InetAddress.getByName(nodeIp) is Inet4Address
        } catch (t: Throwable) {
            false
        }

    /** The network mask for a prefix length, as an Int. */
    private fun maskOf(prefixLen: Int): Int =
        if (prefixLen <= 0) 0 else (-1 shl (32 - prefixLen))

    private fun ipv4ToInt(s: String): Int {
        val parts = s.trim().split(".")
        require(parts.size == 4) { "AllowedIps: $s is not an IPv4 address" }
        var v = 0
        for (p in parts) {
            val o = p.toIntOrNull() ?: throw IllegalArgumentException("AllowedIps: $s")
            require(o in 0..255) { "AllowedIps: $s" }
            v = (v shl 8) or o
        }
        return v
    }

    private fun intToIpv4(v: Int): String =
        "${(v ushr 24) and 0xff}.${(v ushr 16) and 0xff}.${(v ushr 8) and 0xff}.${v and 0xff}"
}
