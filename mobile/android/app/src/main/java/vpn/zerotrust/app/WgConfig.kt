package vpn.zerotrust.app

import com.wireguard.config.Config
import com.wireguard.config.Interface
import com.wireguard.config.Peer
import com.wireguard.crypto.KeyPair

/**
 * Pure-data tunnel config we hand to ZeroTrustVpnService. The translation to
 * a com.wireguard.config.Config happens in [toLibraryConfig] below.
 */
data class WgConfig(
    val privateKey: String,
    val interfaceIP: String,
    /**
     * IPv6 mesh address, or null when the exit node cannot route v6. The
     * peers still claim ::/0 either way: without an address here that
     * blackholes v6 so it cannot escape the tunnel, and with one it carries
     * it. Never drop ::/0 to "fix" v6 not working — that is the leak.
     */
    val interfaceIP6: String? = null,
    val dns: List<String>,
    val peers: List<WgPeer>,
    val multihop: Boolean = false,
    /** Entry and exit are one machine — see WgRegisterResponse.sameHost. */
    val sameHost: Boolean = false,
    /**
     * Set only when this config's packets go through a running local relay.
     * It is the FACT, not the customer's preference: [TunnelBootstrap] leaves
     * it null whenever the node offers no relay, and the UI reads it rather
     * than the setting so a tick mark can never imply a property the traffic
     * does not have.
     */
    val obfs: ObfsRoute? = null,
) {
    /**
     * A live relay this config routes through.
     *
     * @param loopbackPort where the relay is listening; the peer's Endpoint.
     * @param nodeIp       the node's real address, which must be kept OUT of
     *                     the tunnel's routes or the relay's own packets loop
     *                     back into it.
     * @param mtu          reduced by the relay's per-packet overhead.
     */
    data class ObfsRoute(val loopbackPort: Int, val nodeIp: String, val mtu: Int)

    /**
     * Convert to wireguard-android's Config object. This is what gets passed
     * to GoBackend.setState().
     */
    fun toLibraryConfig(): Config {
        val iface = Interface.Builder().apply {
            parseAddresses(
                listOfNotNull(interfaceIP, interfaceIP6).joinToString(", "))
            if (dns.isNotEmpty()) {
                parseDnsServers(dns.joinToString(", "))
            }
            parsePrivateKey(privateKey)
            // Normally no MTU override: wireguard-android picks 1280, which
            // is safe across every carrier network and below anything the
            // control plane would publish. Through the relay it is not a
            // free choice — the transport adds 55 bytes and the control
            // plane says what fits.
            obfs?.let { setMtu(it.mtu) }
        }.build()

        val peerObjs = peers.map { p ->
            Peer.Builder().apply {
                parsePublicKey(p.publicKey)
                // Through the relay the peer is a socket on this device.
                // WireGuard sends there; the relay seals each datagram and
                // carries it the rest of the way.
                parseEndpoint(
                    if (obfs != null) "127.0.0.1:${obfs.loopbackPort}" else p.endpoint)
                if (obfs != null) {
                    // Everything except the node's own address. Without this
                    // the tunnel's default route captures the relay's
                    // upstream socket, WireGuard encrypts the relay's own
                    // packets and sends them back to the relay, and the
                    // tunnel dies in a loop that looks like a broken network.
                    // See AllowedIps for why the arithmetic is tested rather
                    // than eyeballed.
                    parseAllowedIPs(AllowedIps.forRelay(obfs.nodeIp).joinToString(", "))
                } else if (p.allowedIps.isNotEmpty()) {
                    parseAllowedIPs(p.allowedIps.joinToString(", "))
                } else {
                    // Default route — full tunnel
                    parseAllowedIPs("0.0.0.0/0, ::/0")
                }
                if (p.persistentKeepalive > 0) {
                    setPersistentKeepalive(p.persistentKeepalive)
                }
            }.build()
        }

        return Config.Builder()
            .setInterface(iface)
            .addPeers(peerObjs)
            .build()
    }

    companion object {
        /** Generate a fresh Curve25519 keypair using wireguard-android's crypto. */
        fun generateKeypair(): Keypair {
            val kp = KeyPair()
            return Keypair(
                privateKey = kp.privateKey.toBase64(),
                publicKey  = kp.publicKey.toBase64(),
            )
        }
    }
}

data class Keypair(val privateKey: String, val publicKey: String)
