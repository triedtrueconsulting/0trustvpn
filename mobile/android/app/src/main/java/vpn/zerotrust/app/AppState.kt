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
)

/** Server-side region descriptor. Returned by /api/v1/regions and from cache. */
data class Region(val code: String, val name: String)

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
    val regions: List<Region> = DEFAULT_REGIONS,

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
 *   - the encrypted preferences (token, region selection, auto-connect)
 *   - the API client lifecycle
 *   - the connection state machine (mirrors VpnService)
 */
class AppState(app: Application) : AndroidViewModel(app) {

    private val prefs = encryptedPrefs(app)
    private var api: ApiClient = buildApiClient()

    private val _ui = MutableStateFlow(UiState())
    val ui: StateFlow<UiState> = _ui.asStateFlow()

    init {
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

    fun logout() = viewModelScope.launch {
        // Disconnect tunnel if active
        if (_ui.value.tunnel == ConnState.Connected) disconnect()
        prefs.edit().clear().apply()
        _ui.value = UiState()
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
        }
    }

    // ---------------------------------------------------------------
    // Region selection
    // ---------------------------------------------------------------

    fun selectEntry(code: String) {
        prefs.edit().putString(KEY_ENTRY, code).apply()
        _ui.value = _ui.value.copy(entryRegion = code)
    }

    fun selectExit(code: String?) {
        prefs.edit().apply {
            if (code == null) remove(KEY_EXIT) else putString(KEY_EXIT, code)
        }.apply()
        _ui.value = _ui.value.copy(exitRegion = code)
    }

    // ---------------------------------------------------------------
    // Tunnel control — actual VpnService start/stop happens in MainActivity
    // (it needs Activity context to call VpnService.prepare()). This method
    // assumes prepare() has been done and just registers the device + builds
    // the config, then returns it to the caller.
    // ---------------------------------------------------------------

    suspend fun registerDevice(): Result<WgConfig> = withContext(Dispatchers.IO) {
        val keys = WgConfig.generateKeypair()
        val req = WgRegisterRequest(
            pubkey     = keys.publicKey,
            deviceName = "android-${android.os.Build.MODEL}",
            region     = _ui.value.entryRegion,
            exitRegion = _ui.value.exitRegion,
        )
        api.wgRegister(req).map { resp ->
            WgConfig(
                privateKey  = keys.privateKey,
                interfaceIP = resp.interfaceIp,
                dns         = resp.dns,
                peers       = resp.peers,
            )
        }
    }

    fun updateTunnelState(state: ConnState, line: String = "") {
        _ui.value = _ui.value.copy(tunnel = state, statusLine = line)
    }

    fun setError(msg: String?) {
        _ui.value = _ui.value.copy(error = msg)
    }

    // Called from MainActivity once disconnect succeeds
    fun disconnect() = viewModelScope.launch {
        _ui.value = _ui.value.copy(tunnel = ConnState.Disconnecting)
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
        private const val KEY_TOKEN    = "account_token"
        private const val KEY_ENTRY    = "entry_region"
        private const val KEY_EXIT     = "exit_region"
        private const val KEY_API_BASE = "api_base"
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
