package vpn.zerotrust.app

import android.app.Application
import android.content.Context
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Connection state shown in the UI. Transitions are driven by both user
 * actions and VpnService callbacks (which post via [updateTunnelState]).
 */
enum class ConnState { Disconnected, Connecting, Connected, Disconnecting, Failed }

/** Persisted account info, all hashed/stored via EncryptedSharedPreferences. */
data class Account(
    val token: String,
    val expiresAt: Long,
    val daysRemaining: Int,
    val deviceCount: Int,
    val mode: String,
    val plan: String = "paid",
    /** 0 when the control plane did not say; the UI then shows no cap at all
     *  rather than inventing one. */
    val maxDevices: Int = 0,
)

/** Server-side region descriptor. Returned by /api/v1/regions and from cache. */
data class Region(val code: String, val name: String)

/** One registered device, from /api/v1/devices. */
data class Device(
    val pubkey: String,
    val name: String,
    val meshIp: String,
    val lastSeen: Long,
    val multihop: Boolean = false,
    val entryNode: String? = null,
    val exitNode: String? = null,
)

/**
 * Single screen state object. Compose collects this and re-renders the UI.
 */
data class UiState(
    val loggedIn: Boolean = false,
    val loading: Boolean = false,
    val error: String? = null,
    val account: Account? = null,

    val tunnel: ConnState = ConnState.Disconnected,
    val entryRegion: String = "zur",
    val exitRegion: String? = null,         // null = single-hop
    /**
     * What the customer asked for. Rendered on the switch.
     */
    val obfuscate: Boolean = false,
    /**
     * Whether a relay is REALLY carrying this tunnel. Different from
     * [obfuscate] whenever the node routed to runs none, and the hint under
     * the switch reads this one. A control that implies unrecognizable
     * traffic over plain WireGuard is the single worst thing this feature
     * could do.
     */
    val obfuscationActive: Boolean = false,
    val regions: List<Region> = DEFAULT_REGIONS,

    val devices: List<Device> = emptyList(),
    val devicesLoading: Boolean = false,

    /**
     * Messages from the service. There is no email address on this account, so
     * this is the only way a renewal warning ever reaches the customer — the
     * app previously decoded the unread count and never fetched the messages
     * behind it, which delivered nothing.
     */
    val notices: List<NoticeResponse> = emptyList(),
    /** This device's own public key, so the list can mark which row is "this
     *  phone" and refuse to let you delete the tunnel out from under yourself. */
    val thisDevicePubkey: String = "",

    val apiBase: String = "",

    /**
     * The last connect resolved entry and exit to the same machine. True only
     * against a single-VPS test deployment; the UI must stop claiming the
     * traffic crosses a border, because it does not.
     */
    val sameHostRoute: Boolean = false,

    val statusLine: String = "",
)

/**
 * Default region list, used when the app is first launched or the API is
 * unreachable. Synced with the live /api/v1/regions response on each launch.
 */
val DEFAULT_REGIONS = listOf(
    Region("zur", "Zurich, Switzerland"),
    Region("rey", "Reykjavik, Iceland"),
    Region("buc", "Bucharest, Romania"),
)

/**
 * Main app ViewModel. Owns:
 *   - the encrypted preferences (token, device keypair, region selection)
 *   - the API client lifecycle
 *   - the connection state machine (mirrors the tunnel service)
 */
class AppState(app: Application) : AndroidViewModel(app) {

    private val prefs = encryptedPrefs(app)
    private val boot = TunnelBootstrap(prefs)
    private var api: ApiClient = buildApiClient()

    private val _ui = MutableStateFlow(UiState())
    val ui: StateFlow<UiState> = _ui.asStateFlow()

    init {
        _ui.value = _ui.value.copy(
            apiBase = prefs.getString(KEY_API_BASE, null) ?: BuildConfig.DEFAULT_API_BASE,
            thisDevicePubkey = boot.publicKey(),
            obfuscate = boot.obfuscate(),
            // Not restored from a preference: whether a relay is running is a
            // fact about this process, and after a restart there is none.
            obfuscationActive = ObfsRelayHolder.isRunning,
        )
        // Restore the session from encrypted storage. Runs synchronously so
        // the first compose pass already sees the correct logged-in state.
        val token = prefs.getString(KEY_TOKEN, null)
        if (token != null) {
            _ui.value = _ui.value.copy(loggedIn = true)
            refreshAccount()
        }
        // Restore last-used regions
        prefs.getString(KEY_ENTRY, null)?.let { entry ->
            val exit = prefs.getString(KEY_EXIT, null)
            _ui.value = _ui.value.copy(entryRegion = entry, exitRegion = exit)
        }
    }

    // ---------------------------------------------------------------
    // Authentication
    // ---------------------------------------------------------------

    fun login(token: String) = viewModelScope.launch {
        val cleaned = token.trim().replace("\\s+".toRegex(), "")
        if (cleaned.length < 12) {
            _ui.value = _ui.value.copy(error = "Token looks too short")
            return@launch
        }

        _ui.value = _ui.value.copy(loading = true, error = null)
        prefs.edit().putString(KEY_TOKEN, cleaned).apply()
        api = buildApiClient()

        val result = withContext(Dispatchers.IO) { api.accountStatus() }
        result.fold(
            onSuccess = { account ->
                _ui.value = _ui.value.copy(
                    loggedIn = true,
                    loading = false,
                    error = null,
                    account = account,
                )
            },
            onFailure = { err ->
                prefs.edit().remove(KEY_TOKEN).apply()
                _ui.value = _ui.value.copy(
                    loggedIn = false,
                    loading = false,
                    error = err.message ?: "Login failed",
                )
            },
        )
    }

    /**
     * Sign out. Stops the tunnel first, and for real — the old version set the
     * UI to "Disconnecting" and returned, leaving the tunnel carrying traffic
     * for an account the app had just forgotten. It also forgets the device
     * keypair, since that key identifies this device to the control plane.
     */
    fun logout() = viewModelScope.launch {
        ZeroTrustVpnService.disconnect(getApplication())
        prefs.edit().clear().apply()
        _ui.value = UiState(apiBase = BuildConfig.DEFAULT_API_BASE)
        api = buildApiClient()
    }

    // ---------------------------------------------------------------
    // Account refresh (poll on resume)
    // ---------------------------------------------------------------

    fun refreshAccount() = viewModelScope.launch {
        val account = withContext(Dispatchers.IO) {
            api.accountStatus().getOrNull()
        } ?: return@launch
        _ui.value = _ui.value.copy(account = account)
    }

    fun refreshRegions() = viewModelScope.launch {
        val regions = withContext(Dispatchers.IO) {
            api.regions().getOrElse { DEFAULT_REGIONS }
        }
        if (regions.isNotEmpty()) {
            _ui.value = _ui.value.copy(regions = regions)
            // A stale saved selection can name a region the mesh no longer
            // has; connecting with it is a 400 the customer cannot explain.
            reconcileRegions(regions)
        }
    }

    fun refreshDevices() = viewModelScope.launch {
        _ui.value = _ui.value.copy(devicesLoading = true)
        val result = withContext(Dispatchers.IO) { api.devices() }
        _ui.value = result.fold(
            onSuccess = { _ui.value.copy(devices = it, devicesLoading = false) },
            onFailure = { _ui.value.copy(devicesLoading = false,
                                         error = it.message ?: "Could not list devices") },
        )
    }

    /**
     * Pull the messages waiting for this account.
     *
     * There is no email address on file — that is the product — so this is the
     * only channel the service has to reach a customer, including the warning
     * that a subscription is about to run out. The app used to decode the
     * unread COUNT from /account/status and never fetch the messages behind
     * it, so nothing was ever delivered.
     *
     * Failure is silent on purpose: this runs alongside the status refresh and
     * a control plane that cannot be reached has already surfaced an error.
     */
    fun refreshNotices() = viewModelScope.launch {
        val result = withContext(Dispatchers.IO) { api.notices() }
        result.onSuccess { list -> _ui.value = _ui.value.copy(notices = list) }
    }

    /** Dismiss one, so it stops coming back on the next refresh. */
    fun dismissNotice(id: Long) = viewModelScope.launch {
        val result = withContext(Dispatchers.IO) { api.markNoticeRead(id) }
        result.onSuccess {
            _ui.value = _ui.value.copy(
                notices = _ui.value.notices.filterNot { it.id == id })
        }
    }

    /**
     * Free a device slot. The cap is not survivable without this: registering
     * is capped, so a customer who filled it from other machines had no way to
     * connect this one, and nothing in the app to tell them why.
     */
    fun removeDevice(pubkey: String) = viewModelScope.launch {
        val result = withContext(Dispatchers.IO) { api.deleteDevice(pubkey) }
        result.fold(
            onSuccess = {
                _ui.value = _ui.value.copy(
                    devices = _ui.value.devices.filterNot { it.pubkey == pubkey },
                )
                refreshAccount()
            },
            onFailure = { _ui.value = _ui.value.copy(error = it.message ?: "Remove failed") },
        )
    }

    // ---------------------------------------------------------------
    // Region selection
    // ---------------------------------------------------------------

    fun selectEntry(code: String) {
        prefs.edit().putString(KEY_ENTRY, code).apply()
        _ui.value = _ui.value.copy(entryRegion = code)
        // Multi-hop requires entry != exit; the API rejects the pair outright.
        // Picking the exit you already had as your entry is an easy thing to
        // do in two taps, so move the exit rather than fail the connect.
        if (_ui.value.exitRegion == code) {
            selectExit(_ui.value.regions.firstOrNull { it.code != code }?.code)
        }
    }

    /**
     * Turn DPI protection on or off. Applies on the NEXT connect: the
     * transport is chosen when the tunnel is built, and swapping it under a
     * live one means tearing the tunnel down, which is not a thing to do to
     * somebody who tapped a switch.
     */
    fun setObfuscate(on: Boolean) {
        boot.setObfuscate(on)
        _ui.value = _ui.value.copy(obfuscate = on)
    }

    fun selectExit(code: String?) {
        if (code != null && code == _ui.value.entryRegion) return
        prefs.edit().apply {
            if (code == null) remove(KEY_EXIT) else putString(KEY_EXIT, code)
        }.apply()
        _ui.value = _ui.value.copy(exitRegion = code)
    }

    private fun reconcileRegions(regions: List<Region>) {
        val codes = regions.map { it.code }.toSet()
        if (_ui.value.entryRegion !in codes) {
            regions.firstOrNull()?.let { selectEntry(it.code) }
        }
        val exit = _ui.value.exitRegion
        if (exit != null && (exit !in codes || exit == _ui.value.entryRegion)) {
            selectExit(regions.firstOrNull { it.code != _ui.value.entryRegion }?.code)
        }
    }

    // ---------------------------------------------------------------
    // Control-plane address (self-hosted deployments)
    // ---------------------------------------------------------------

    fun setApiBase(raw: String) {
        val base = raw.trim().trimEnd('/')
        val effective = if (base.isEmpty()) BuildConfig.DEFAULT_API_BASE else base
        if (!effective.startsWith("https://") && !effective.startsWith("http://")) {
            _ui.value = _ui.value.copy(error = "Address must start with https://")
            return
        }
        prefs.edit().apply {
            if (base.isEmpty()) remove(KEY_API_BASE) else putString(KEY_API_BASE, base)
        }.apply()
        api = buildApiClient()
        _ui.value = _ui.value.copy(apiBase = effective, error = null)
        if (_ui.value.loggedIn) refreshAccount()
    }

    // ---------------------------------------------------------------
    // Tunnel control — actual VpnService start/stop happens in MainActivity
    // (it needs Activity context to call VpnService.prepare()). This method
    // assumes prepare() has been done and just registers the device + builds
    // the config, then returns it to the caller.
    // ---------------------------------------------------------------

    suspend fun registerDevice(): Result<WgConfig> = withContext(Dispatchers.IO) {
        val cfg = runCatching { boot.register() }
        cfg.getOrNull()?.let {
            _ui.value = _ui.value.copy(
                thisDevicePubkey = boot.publicKey(),
                sameHostRoute = it.multihop && it.sameHost,
                // it.obfs is non-null only when a relay actually started for
                // this config. Reading boot.obfuscate() here instead would
                // report the wish as the fact.
                obfuscationActive = it.obfs != null,
            )
        }
        cfg
    }

    fun updateTunnelState(state: ConnState, line: String = "") {
        _ui.value = _ui.value.copy(tunnel = state, statusLine = line)
    }

    fun setError(msg: String?) {
        _ui.value = _ui.value.copy(error = msg)
    }

    // ---------------------------------------------------------------
    // Internal: API client wiring
    // ---------------------------------------------------------------

    private fun buildApiClient(): ApiClient {
        val token = prefs.getString(KEY_TOKEN, null) ?: ""
        val base = prefs.getString(KEY_API_BASE, null) ?: BuildConfig.DEFAULT_API_BASE
        return ApiClient(baseUrl = base, token = token)
    }

    companion object {
        // Key names live in TunnelBootstrap: the service reads the same
        // preferences without going through this ViewModel, and two lists of
        // string literals is how those two views of the same store drift.
        private const val KEY_TOKEN    = TunnelBootstrap.KEY_TOKEN
        private const val KEY_ENTRY    = TunnelBootstrap.KEY_ENTRY
        private const val KEY_EXIT     = TunnelBootstrap.KEY_EXIT
        private const val KEY_API_BASE = TunnelBootstrap.KEY_API_BASE
        private const val PREFS_FILE   = "zerotrust_secure"

        fun encryptedPrefs(ctx: Context) = EncryptedSharedPreferences.create(
            ctx,
            PREFS_FILE,
            MasterKey.Builder(ctx)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build(),
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }
}
