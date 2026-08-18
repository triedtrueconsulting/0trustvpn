package vpn.zerotrust.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
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
 * Foreground VpnService that runs the actual WireGuard tunnel.
 *
 * Lifecycle:
 *   - MainActivity calls VpnService.prepare() to get the system VPN consent
 *   - User grants consent -> activity starts this service via ACTION_CONNECT
 *   - Service brings up the tunnel, posts the foreground notification,
 *     and stays alive until ACTION_DISCONNECT
 *
 * We deliberately keep the service stateless w.r.t. account/token concerns;
 * AppState in the UI process owns those. The service receives a complete
 * WgConfig as a byte string in the intent and just applies it.
 */
class ZeroTrustVpnService : VpnService() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var backend: GoBackend? = null
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
            ACTION_DISCONNECT -> {
                disconnect()
            }
            else -> {
                Log.w(TAG, "Unexpected intent action: ${intent?.action}")
            }
        }
        return START_STICKY
    }

    private fun connect(configString: String) {
        startForeground(NOTIF_ID, buildNotification("Connecting…", subtitle = "Negotiating tunnel"))
        scope.launch {
            try {
                val backend = getOrCreateBackend()
                val cfg = Config.parse(configString.byteInputStream())
                val tun = ZeroTrustTunnel().also { tunnel = it }

                withContext(Dispatchers.IO) {
                    backend.setState(tun, Tunnel.State.UP, cfg)
                }

                broadcast(ConnState.Connected, "Tunnel up")
                startForeground(NOTIF_ID, buildNotification(
                    title = "0trust VPN connected",
                    subtitle = describeRoute(cfg),
                ))
            } catch (t: Throwable) {
                Log.e(TAG, "connect failed", t)
                broadcast(ConnState.Failed, t.message ?: "Connect failed")
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
    }

    private fun disconnect() {
        scope.launch {
            try {
                val backend = backend ?: return@launch
                val tun = tunnel ?: return@launch
                withContext(Dispatchers.IO) {
                    backend.setState(tun, Tunnel.State.DOWN, null)
                }
            } catch (t: Throwable) {
                Log.w(TAG, "disconnect: $t")
            } finally {
                broadcast(ConnState.Disconnected, "")
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
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

    // --- Backend & Tunnel -----------------------------------------------

    private fun getOrCreateBackend(): GoBackend {
        backend?.let { return it }
        // The wireguard-android library wires up its own VpnService bridge
        // via this VpnServiceFactory hook.
        val b = GoBackend(this)
        backend = b
        return b
    }

    /** Trivial Tunnel impl — wireguard-android requires it but we just need a name. */
    private inner class ZeroTrustTunnel : Tunnel {
        override fun getName() = "0trust0"
        override fun onStateChange(newState: Tunnel.State) {
            Log.i(TAG, "tunnel state -> $newState")
        }
    }

    companion object {
        private const val TAG = "0trust-vpn"

        const val ACTION_CONNECT    = "vpn.zerotrust.action.CONNECT"
        const val ACTION_DISCONNECT = "vpn.zerotrust.action.DISCONNECT"
        const val EXTRA_CONFIG      = "vpn.zerotrust.extra.CONFIG"

        const val BROADCAST_STATE   = "vpn.zerotrust.broadcast.STATE"
        const val EXTRA_STATE       = "state"
        const val EXTRA_STATUS_LINE = "line"

        const val CHANNEL_ID = "0trust_tunnel"
        const val NOTIF_ID   = 1

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
    }
}
