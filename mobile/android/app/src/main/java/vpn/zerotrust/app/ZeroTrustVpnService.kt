package vpn.zerotrust.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import com.wireguard.android.backend.Backend
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Foreground service that owns the 0trust tunnel's lifecycle and notification.
 *
 * It is deliberately NOT a [android.net.VpnService].
 *
 * The tunnel itself is run by wireguard-android's [GoBackend], and GoBackend
 * brings up its own `GoBackend$VpnService` — declared in the library's AAR
 * manifest — to call `VpnService.Builder.establish()`. This class used to also
 * extend VpnService and declare the `android.net.VpnService` intent filter,
 * which left the merged manifest with two of them. That is not a cosmetic
 * duplication: Android resolves an app's always-on VPN service by querying for
 * that intent filter and requires exactly one match, so declaring a second one
 * made "Always-on VPN" impossible to enable for this app — while the extra
 * VpnService never called establish() and so never carried a packet.
 *
 * One VpnService (the library's), one foreground service (this one).
 *
 * Lifecycle:
 *   - MainActivity calls VpnService.prepare() to get the system VPN consent
 *   - User grants consent -> activity starts this service via ACTION_CONNECT
 *   - This service drives GoBackend, posts the notification, and stays alive
 *     until ACTION_DISCONNECT
 *
 * The service is stateless w.r.t. account/token concerns; AppState owns those.
 * It receives a complete wg-quick config in the intent and just applies it.
 */
class ZeroTrustVpnService : Service() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var tunnel: ZeroTrustTunnel? = null

    override fun onCreate() {
        super.onCreate()
        ensureNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                val configString = intent.getStringExtra(EXTRA_CONFIG)
                if (configString.isNullOrBlank()) {
                    Log.e(TAG, "ACTION_CONNECT without config")
                    stopSelf()
                    return START_NOT_STICKY
                }
                connect(configString)
            }
            ACTION_DISCONNECT -> disconnect()
            ACTION_RECONNECT -> reconnect()
            else -> {
                // START_NOT_STICKY below means we should not normally be
                // restarted with a null intent, but a null action can still
                // arrive. Never sit here started-but-not-foreground: Android
                // kills the process with ForegroundServiceDidNotStartInTime.
                Log.w(TAG, "Unexpected intent action: ${intent?.action} — stopping")
                stopForegroundAndSelf()
                return START_NOT_STICKY
            }
        }
        // Not STICKY: a restart with a null intent has no config to apply, and
        // silently coming back up without a tunnel while showing a "connected"
        // notification is the worst failure mode a VPN client has.
        return START_NOT_STICKY
    }

    private fun connect(configString: String) {
        foreground(buildNotification("Connecting…", subtitle = "Negotiating tunnel"))
        scope.launch {
            try {
                val backend = backend(this@ZeroTrustVpnService)
                val cfg = Config.parse(configString.byteInputStream())
                val tun = ZeroTrustTunnel().also { tunnel = it }

                withContext(Dispatchers.IO) {
                    backend.setState(tun, Tunnel.State.UP, cfg)
                }

                broadcast(ConnState.Connected, "Tunnel up")
                foreground(buildNotification(
                    title = "0trust VPN connected",
                    subtitle = describeRoute(cfg),
                ))
            } catch (t: Throwable) {
                Log.e(TAG, "connect failed", t)
                broadcast(ConnState.Failed, t.message ?: "Connect failed")
                stopForegroundAndSelf()
            }
        }
    }

    private fun disconnect() {
        scope.launch {
            try {
                val tun = tunnel ?: knownTunnel()
                if (tun != null) {
                    withContext(Dispatchers.IO) {
                        backend(this@ZeroTrustVpnService).setState(tun, Tunnel.State.DOWN, null)
                    }
                }
            } catch (t: Throwable) {
                Log.w(TAG, "disconnect: $t")
            } finally {
                tunnel = null
                broadcast(ConnState.Disconnected, "")
                stopForegroundAndSelf()
            }
        }
    }

    /**
     * Bring the tunnel back up with no UI in front of us: used after a reboot.
     *
     * Everything needed is already in EncryptedSharedPreferences — the account
     * token and this device's keypair — so the service can register and connect
     * on its own. What it cannot do is ask for VPN consent: that needs an
     * Activity. If consent is not already granted we say so in the
     * notification rather than failing silently.
     */
    private fun reconnect() {
        foreground(buildNotification("Reconnecting…", subtitle = "0trust VPN"))
        if (VpnService.prepare(this) != null) {
            Log.w(TAG, "no VPN consent — cannot reconnect without the UI")
            foreground(buildNotification(
                title = "0trust VPN needs permission",
                subtitle = "Open the app to reconnect",
            ))
            return
        }
        scope.launch {
            val prefs = AppState.encryptedPrefs(this@ZeroTrustVpnService)
            val cfg = runCatching { TunnelBootstrap(prefs).buildConfig() }.getOrNull()
            if (cfg == null) {
                Log.w(TAG, "reconnect: could not obtain a config")
                broadcast(ConnState.Failed, "Reconnect failed")
                stopForegroundAndSelf()
                return@launch
            }
            connect(cfg)
        }
    }

    /**
     * After a process restart this service instance has no tunnel object, but
     * the backend may still be carrying one. Ask it, so "Disconnect" from the
     * notification actually takes the tunnel down instead of only dismissing
     * the notification and leaving traffic flowing.
     */
    private fun knownTunnel(): Tunnel? {
        val names = runCatching { backend(this).runningTunnelNames }.getOrNull().orEmpty()
        return if (TUNNEL_NAME in names) ZeroTrustTunnel() else null
    }

    /**
     * Android 14 wants the foreground-service type at the call site. The type
     * is `specialUse`: the tunnel itself is run by the library's VpnService,
     * and this service exists to own the ongoing notification and its
     * Disconnect action for as long as that tunnel is up.
     */
    private fun foreground(n: Notification) {
        ServiceCompat.startForeground(
            this, NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
    }

    private fun stopForegroundAndSelf() {
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    // --- Notification & broadcast ---------------------------------------

    private fun ensureNotificationChannel() {
        val nm = getSystemService(NotificationManager::class.java)
        if (nm.getNotificationChannel(CHANNEL_ID) == null) {
            val ch = NotificationChannel(
                CHANNEL_ID,
                "VPN connection",
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = "Persistent notification while the 0trust tunnel is active"
                setShowBadge(false)
            }
            nm.createNotificationChannel(ch)
        }
    }

    private fun buildNotification(title: String, subtitle: String): Notification {
        val openApp = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val disconnect = PendingIntent.getService(
            this, 1,
            Intent(this, ZeroTrustVpnService::class.java).setAction(ACTION_DISCONNECT),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(title)
            .setContentText(subtitle)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setContentIntent(openApp)
            .addAction(0, "Disconnect", disconnect)
            .build()
    }

    private fun describeRoute(cfg: Config): String {
        val peer = cfg.peers.firstOrNull() ?: return "tunnel active"
        // peer.endpoint is java.util.Optional<InetEndpoint>; use orElse(null)
        val endpoint = peer.endpoint.orElse(null)?.toString() ?: "unknown peer"
        return "via $endpoint"
    }

    private fun broadcast(state: ConnState, line: String) {
        val intent = Intent(BROADCAST_STATE)
            .putExtra(EXTRA_STATE, state.name)
            .putExtra(EXTRA_STATUS_LINE, line)
            .setPackage(packageName)
        sendBroadcast(intent)
    }

    /** Trivial Tunnel impl — wireguard-android requires it but we just need a name. */
    private inner class ZeroTrustTunnel : Tunnel {
        override fun getName() = TUNNEL_NAME
        override fun onStateChange(newState: Tunnel.State) {
            Log.i(TAG, "tunnel state -> $newState")
            if (newState == Tunnel.State.DOWN) broadcast(ConnState.Disconnected, "")
        }
    }

    companion object {
        private const val TAG = "0trust-vpn"

        /** Matches the interface name the desktop client uses. */
        const val TUNNEL_NAME = "0trust0"

        const val ACTION_CONNECT    = "vpn.zerotrust.action.CONNECT"
        const val ACTION_DISCONNECT = "vpn.zerotrust.action.DISCONNECT"
        const val ACTION_RECONNECT  = "vpn.zerotrust.action.RECONNECT"
        const val EXTRA_CONFIG      = "vpn.zerotrust.extra.CONFIG"

        const val BROADCAST_STATE   = "vpn.zerotrust.broadcast.STATE"
        const val EXTRA_STATE       = "state"
        const val EXTRA_STATUS_LINE = "line"

        const val CHANNEL_ID = "0trust_tunnel"
        const val NOTIF_ID   = 1

        /**
         * One backend per process. GoBackend holds the binding to its own
         * VpnService; making a new one per connect leaks that binding and can
         * leave a tunnel nothing is tracking.
         */
        @Volatile private var sharedBackend: Backend? = null

        fun backend(ctx: Context): Backend {
            // Read the volatile into a local before using it: `sharedBackend ?:`
            // reads the field twice and Kotlin will not smart-cast a mutable
            // property that another thread could change between the two.
            val cached = sharedBackend
            if (cached != null) return cached
            return synchronized(this) {
                val existing = sharedBackend
                existing ?: GoBackend(ctx.applicationContext).also { sharedBackend = it }
            }
        }

        fun connect(ctx: Context, configString: String) {
            ctx.startForegroundService(
                Intent(ctx, ZeroTrustVpnService::class.java).apply {
                    action = ACTION_CONNECT
                    putExtra(EXTRA_CONFIG, configString)
                }
            )
        }

        fun disconnect(ctx: Context) {
            ctx.startService(
                Intent(ctx, ZeroTrustVpnService::class.java).apply {
                    action = ACTION_DISCONNECT
                }
            )
        }

        /** Used by [BootReceiver]; no Activity involved. */
        fun reconnect(ctx: Context) {
            ctx.startForegroundService(
                Intent(ctx, ZeroTrustVpnService::class.java).apply {
                    action = ACTION_RECONNECT
                }
            )
        }
    }
}
