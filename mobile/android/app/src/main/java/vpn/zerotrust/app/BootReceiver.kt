package vpn.zerotrust.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * Reconnect the tunnel on device boot if the user has the "Auto-connect
 * on startup" toggle enabled. The toggle is stored in EncryptedSharedPreferences
 * alongside the account token, so we can check it without bringing up the UI.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, intent: Intent?) {
        if (intent?.action != Intent.ACTION_BOOT_COMPLETED &&
            intent?.action != "android.intent.action.QUICKBOOT_POWERON") return

        val prefs = AppState.encryptedPrefs(ctx)
        val autoConnect = prefs.getBoolean("auto_connect", false)
        val token = prefs.getString("account_token", null)
        if (!autoConnect || token.isNullOrEmpty()) return

        Log.i("0trust-boot", "auto-connect enabled — launching main activity to reconnect")
        // We can't directly call VpnService.prepare() from a receiver because
        // it requires Activity context for the consent dialog. Instead, start
        // the MainActivity with an "auto-connect" hint; MainActivity does the
        // prepare() flow and reconnects without showing the UI if consent
        // has already been granted (which it will have, since the user
        // connected at least once before enabling auto-connect).
        ctx.startActivity(
            Intent(ctx, MainActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                putExtra("auto_connect_on_launch", true)
            }
        )
    }
}
