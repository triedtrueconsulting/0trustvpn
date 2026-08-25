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
        )
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
    }
}
