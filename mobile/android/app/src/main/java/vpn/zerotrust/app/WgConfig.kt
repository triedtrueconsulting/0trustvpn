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
) {
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
            // No MTU override: wireguard-android picks 1280 by default
            // which is safe across all carrier networks.
        }.build()

        val peerObjs = peers.map { p ->
            Peer.Builder().apply {
                parsePublicKey(p.publicKey)
                parseEndpoint(p.endpoint)
                if (p.allowedIps.isNotEmpty()) {
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
