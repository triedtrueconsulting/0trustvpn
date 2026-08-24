package vpn.zerotrust.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * Reconnect the tunnel on device boot if the user has "Reconnect after
 * restart" enabled.
 *
 * Two things about this were wrong before and are worth spelling out, because
 * both fail silently and neither shows up in a build:
 *
 *  - The receiver was declared `android:exported="false"`. BOOT_COMPLETED is
 *    sent by the system, which is a different uid, so a non-exported receiver
 *    never sees it. The toggle in Settings did nothing at all.
 *
 *  - It then tried to start MainActivity to do the reconnect. Android 10
 *    forbids starting an activity from the background, so even once the
 *    broadcast arrived the reconnect would have been dropped.
 *
 * Starting a foreground service is the supported path — receiving
 * BOOT_COMPLETED is one of the documented exemptions from the background
 * foreground-service start restriction — and the service can do the whole job
 * without a UI, because the account token and this device's keypair are
 * already in EncryptedSharedPreferences.
 *
 * The system's own Always-on VPN setting is still the more reliable option and
 * Settings points at it; this covers the users who have not turned it on.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, intent: Intent?) {
        if (intent?.action != Intent.ACTION_BOOT_COMPLETED &&
            intent?.action != "android.intent.action.QUICKBOOT_POWERON") return

        val prefs = AppState.encryptedPrefs(ctx)
        val autoConnect = prefs.getBoolean(TunnelBootstrap.KEY_AUTO_CONNECT, false)
        val token = prefs.getString(TunnelBootstrap.KEY_TOKEN, null)
        if (!autoConnect || token.isNullOrEmpty()) return

        Log.i("0trust-boot", "auto-connect enabled — starting the tunnel service")
        ZeroTrustVpnService.reconnect(ctx)
    }
}
