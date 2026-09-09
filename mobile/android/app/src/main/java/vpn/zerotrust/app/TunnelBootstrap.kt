package vpn.zerotrust.app

import android.content.SharedPreferences
import android.os.Build

/**
 * Everything needed to turn stored credentials into a tunnel config.
 *
 * This exists as one class, used by both the UI and the service, because the
 * two paths that need it — the user pressing Connect, and the boot receiver
 * reconnecting with no UI — must agree on the device's identity. When the
 * registration logic lived only in the ViewModel, the service had no way to
 * reach it; and when the keypair was generated inline at each call site, every
 * connect registered a brand new device and burned an account slot until the
 * cap locked the customer out.
 */
class TunnelBootstrap(private val prefs: SharedPreferences) {

    /**
     * This device's WireGuard keypair, generated once and kept.
     *
     * Registration is idempotent on the public key: re-presenting the same key
     * returns the same device and the same mesh IP. The private key never
     * leaves EncryptedSharedPreferences and is never sent to the control plane.
     */
    fun keypair(): Keypair {
        val priv = prefs.getString(KEY_WG_PRIV, null)
        val pub  = prefs.getString(KEY_WG_PUB, null)
        if (!priv.isNullOrEmpty() && !pub.isNullOrEmpty()) return Keypair(priv, pub)

        val fresh = WgConfig.generateKeypair()
        prefs.edit()
            .putString(KEY_WG_PRIV, fresh.privateKey)
            .putString(KEY_WG_PUB, fresh.publicKey)
            .apply()
        return fresh
    }

    fun publicKey(): String = prefs.getString(KEY_WG_PUB, "") ?: ""

    fun token(): String = prefs.getString(KEY_TOKEN, "") ?: ""

    fun apiBase(): String =
        prefs.getString(KEY_API_BASE, null) ?: BuildConfig.DEFAULT_API_BASE

    fun entryRegion(): String = prefs.getString(KEY_ENTRY, null) ?: "zur"

    /** null means single-hop. Never equal to the entry region. */
    fun exitRegion(): String? =
        prefs.getString(KEY_EXIT, null)?.takeIf { it != entryRegion() }

    /**
     * Whether the customer has asked for DPI protection. Off by default and
     * sticky, like the kill switch on desktop: a protection you must remember
     * to re-enable on every connect is not one you can rely on.
     *
     * This is the WISH. Whether it is granted depends on the node the
     * control plane routes to — see [register].
     */
    fun obfuscate(): Boolean = prefs.getBoolean(KEY_OBFUSCATE, false)

    fun setObfuscate(on: Boolean) {
        prefs.edit().putBoolean(KEY_OBFUSCATE, on).apply()
    }

    fun deviceName(): String = "android-${Build.MODEL}".take(64)

    /** Register (idempotently) and return the tunnel config, or throw. */
    fun register(): WgConfig {
        val tok = token()
        if (tok.isEmpty()) throw IllegalStateException("no account token stored")
        val keys = keypair()
        val api = ApiClient(apiBase(), tok)
        val resp = api.wgRegister(
            WgRegisterRequest(
                pubkey     = keys.publicKey,
                deviceName = deviceName(),
                region     = entryRegion(),
                exitRegion = exitRegion(),
            )
        ).getOrThrow()
        // The API raises 503 rather than handing back an empty peer list, but a
        // client that indexes [0] on trust panics the one time that changes.
        if (resp.peers.isEmpty()) {
            throw IllegalStateException("No exit node available right now")
        }
        return WgConfig(
            privateKey   = keys.privateKey,
            interfaceIP  = resp.interfaceIp,
            interfaceIP6 = resp.interfaceIp6,
            dns          = resp.dns,
            peers        = resp.peers,
            multihop     = resp.multihop,
            sameHost     = resp.sameHost,
            obfs         = startRelayIfWanted(resp),
        )
    }

    /**
     * Bring up the local relay when the customer wants obfuscation and the
     * node they landed on can provide it, and return what the tunnel config
     * needs to know about it. Null means a direct tunnel.
     *
     * Every "no" here is a normal outcome, not an error, and each one leaves
     * the customer with a working direct tunnel — but the UI must then say
     * the traffic is NOT obfuscated, which is why this returns the fact
     * rather than setting a flag from the preference.
     */
    private fun startRelayIfWanted(resp: WgRegisterResponse): WgConfig.ObfsRoute? {
        ObfsRelayHolder.stop()          // never leave a previous one running
        if (!obfuscate()) return null

        val ob = resp.obfuscation ?: return null
        if (ob.kind != "shadowsocks") return null
        val nodeIp = resp.peers.firstOrNull()?.endpoint
            ?.substringBeforeLast(':')?.trim('[', ']') ?: return null
        // A v6 node address would need the v6 route complement too, which is
        // not implemented. Refusing here gives a direct tunnel; going ahead
        // would give an obfuscated one whose packets loop.
        if (!AllowedIps.supportsExclusion(nodeIp)) return null

        val relayHost = ob.endpoint.substringBeforeLast(':')
        val relayPort = ob.endpoint.substringAfterLast(':').toIntOrNull() ?: return null
        val targetHost = ob.target.substringBeforeLast(':')
        val targetPort = ob.target.substringAfterLast(':').toIntOrNull() ?: return null
        val mtu = if (ob.mtu > 0) ob.mtu else resp.mtu
        if (mtu <= 0) return null

        return try {
            val local = ObfsRelayHolder.restart(
                relayHost, relayPort, ob.key,
                java.net.InetSocketAddress(targetHost, targetPort))
            WgConfig.ObfsRoute(loopbackPort = local, nodeIp = nodeIp, mtu = mtu)
        } catch (t: Throwable) {
            ObfsRelayHolder.stop()
            null
        }
    }

    /** Register and render straight to a wg-quick config string. */
    fun buildConfig(): String = register().toLibraryConfig().toWgQuickString()

    companion object {
        const val KEY_TOKEN        = "account_token"
        const val KEY_AUTO_CONNECT = "auto_connect"
        const val KEY_ENTRY        = "entry_region"
        const val KEY_EXIT         = "exit_region"
        const val KEY_API_BASE     = "api_base"
        const val KEY_WG_PRIV      = "wg_private_key"
        const val KEY_WG_PUB       = "wg_public_key"
        const val KEY_OBFUSCATE    = "obfuscate"
    }
}
