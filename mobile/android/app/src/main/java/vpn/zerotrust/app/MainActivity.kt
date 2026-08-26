package vpn.zerotrust.app

import android.Manifest
import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.viewmodel.compose.viewModel
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {

    private val state: AppState by viewModels()

    /** Broadcast receiver that listens to VpnService state updates. */
    private val stateReceiver = object : BroadcastReceiver() {
        override fun onReceive(ctx: Context, intent: Intent) {
            val name = intent.getStringExtra(ZeroTrustVpnService.EXTRA_STATE) ?: return
            val line = intent.getStringExtra(ZeroTrustVpnService.EXTRA_STATUS_LINE) ?: ""
            val s = runCatching { ConnState.valueOf(name) }.getOrNull() ?: return
            state.updateTunnelState(s, line)
        }
    }

    /** VpnService.prepare() launcher — system VPN-consent dialog. */
    private val vpnConsentLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == Activity.RESULT_OK) {
                bringTunnelUp()
            } else {
                state.updateTunnelState(ConnState.Failed, "VPN permission denied")
            }
        }

    /** Notification permission (Android 13+). */
    private val notifPermLauncher =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) {
            // The user's choice doesn't gate connect — the service runs
            // either way. If they declined, they just won't see the
            // persistent notification (which Android still requires for
            // foreground services, but renders silently).
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        maybeRequestNotificationPermission()
        ContextCompat.registerReceiver(
            this,
            stateReceiver,
            IntentFilter(ZeroTrustVpnService.BROADCAST_STATE),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )

        // If launched by BootReceiver with the "auto-connect" hint,
        // queue up an immediate tunnel-up after composition.
        val autoConnect = intent.getBooleanExtra("auto_connect_on_launch", false)

        setContent {
            ZeroTrustTheme {
                Surface(color = MaterialTheme.colorScheme.background) {
                    val viewModel: AppState = viewModel()
                    val ui by viewModel.ui.collectAsState()

                    LaunchedEffect(ui.loggedIn) {
                        if (ui.loggedIn) {
                            viewModel.refreshAccount()
                            viewModel.refreshRegions()
                            viewModel.refreshDevices()
                            if (autoConnect && ui.tunnel == ConnState.Disconnected) {
                                requestConnect()
                            }
                        }
                    }

                    if (!ui.loggedIn) {
                        LoginScreen(ui = ui, onLogin = { viewModel.login(it) })
                    } else {
                        MainScreen(
                            ui = ui,
                            onConnect = { requestConnect() },
                            onDisconnect = { requestDisconnect() },
                            onSelectEntry = { viewModel.selectEntry(it) },
                            onSelectExit = { viewModel.selectExit(it) },
                            onLogout = { viewModel.logout() },
                            onRefreshDevices = { viewModel.refreshDevices() },
                            onRemoveDevice = { viewModel.removeDevice(it) },
                            onSetApiBase = { viewModel.setApiBase(it) },
                            onDismissError = { viewModel.setError(null) },
                        )
                    }
                }
            }
        }
    }

    override fun onDestroy() {
        unregisterReceiver(stateReceiver)
        super.onDestroy()
    }

    private fun maybeRequestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val granted = ActivityCompat.checkSelfPermission(
                this, Manifest.permission.POST_NOTIFICATIONS,
            ) == PackageManager.PERMISSION_GRANTED
            if (!granted) {
                notifPermLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
    }

    /** Kick the system VPN consent dialog (idempotent if already granted). */
    private fun requestConnect() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnConsentLauncher.launch(intent)
        } else {
            bringTunnelUp()
        }
    }

    private fun bringTunnelUp() {
        state.updateTunnelState(ConnState.Connecting, "Registering device with control plane…")
        lifecycleScope.launch {
            state.registerDevice().fold(
                onSuccess = { cfg ->
                    val text = cfg.toLibraryConfig().toWgQuickString()
                    ZeroTrustVpnService.connect(this@MainActivity, text)
                },
                onFailure = { err ->
                    state.updateTunnelState(ConnState.Failed, err.message ?: "register failed")
                },
            )
        }
    }

    private fun requestDisconnect() {
        state.updateTunnelState(ConnState.Disconnecting, "")
        ZeroTrustVpnService.disconnect(this)
    }
}

// ----------------------------------------------------------------------------
//  LOGIN SCREEN
// ----------------------------------------------------------------------------

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LoginScreen(ui: UiState, onLogin: (String) -> Unit) {
    var token by remember { mutableStateOf("") }
    val focus = LocalFocusManager.current

    Column(
        Modifier
            .fillMaxSize()
            .padding(horizontal = 28.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(20.dp),
    ) {
        Spacer(Modifier.height(48.dp))

        Brand()
        Spacer(Modifier.height(28.dp))

        Text(
            "Welcome.",
            style = MaterialTheme.typography.displayLarge,
            color = ZT_Ink,
        )
        Text(
            "Paste your account token to begin. It's a single 16-character " +
            "string — no email, no password, no recovery flow. Keep it safe.",
            color = ZT_InkDim,
            fontSize = 15.sp,
        )

        Spacer(Modifier.height(16.dp))

        OutlinedTextField(
            value = token,
            onValueChange = { token = it },
            label = { Text("Account token") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            modifier = Modifier.fillMaxWidth(),
        )

        if (ui.error != null) {
            Text(ui.error, color = ZT_Terra, fontSize = 13.sp)
        }

        Button(
            onClick = { focus.clearFocus(); onLogin(token) },
            enabled = !ui.loading && token.isNotBlank(),
            modifier = Modifier.fillMaxWidth().height(56.dp),
            shape = RoundedCornerShape(2.dp),
        ) {
            if (ui.loading) {
                CircularProgressIndicator(
                    color = MaterialTheme.colorScheme.onPrimary,
                    strokeWidth = 2.dp,
                    modifier = Modifier.size(20.dp),
                )
            } else {
                Text("Connect", letterSpacing = 1.4.sp)
            }
        }

        Spacer(Modifier.height(8.dp))
        Text(
            "Don't have a token yet? Visit 0trustvpn.com and pay with Bitcoin. " +
            "You'll receive your token immediately on payment confirmation.",
            color = ZT_InkFnt,
            fontSize = 12.sp,
        )
        Spacer(Modifier.height(48.dp))
    }
}

// ----------------------------------------------------------------------------
//  MAIN SCREEN (logged-in)
// ----------------------------------------------------------------------------

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(
    ui: UiState,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
    onSelectEntry: (String) -> Unit,
    onSelectExit: (String?) -> Unit,
    onLogout: () -> Unit,
    onRefreshDevices: () -> Unit,
    onRemoveDevice: (String) -> Unit,
    onSetApiBase: (String) -> Unit,
    onDismissError: () -> Unit,
) {
    var settingsOpen by remember { mutableStateOf(false) }

    Column(
        Modifier
            .fillMaxSize()
            .padding(horizontal = 24.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(20.dp),
    ) {
        Spacer(Modifier.height(36.dp))

        Row(verticalAlignment = Alignment.CenterVertically) {
            Brand()
            Spacer(Modifier.weight(1f))
            IconButton(onClick = { settingsOpen = true }) {
                Icon(Icons.Outlined.Settings, "Settings", tint = ZT_InkDim)
            }
        }

        Spacer(Modifier.height(12.dp))

        // Errors used to be shown on the login screen only, so anything that
        // went wrong after sign-in — a failed register, a device removal that
        // did not take — happened in silence.
        if (ui.error != null) ErrorBanner(ui.error, onDismissError)

        ConnectionCard(ui = ui, onConnect = onConnect, onDisconnect = onDisconnect)
        RoutingCard(
            ui = ui,
            onSelectEntry = onSelectEntry,
            onSelectExit = onSelectExit,
        )
        AccountCard(ui = ui)
        DevicesCard(
            ui = ui,
            onRefresh = onRefreshDevices,
            onRemove = onRemoveDevice,
        )

        Spacer(Modifier.height(20.dp))
        Text(
            "Switzerland · Iceland · Romania — three jurisdictions outside any Eyes alliance",
            color = ZT_InkFnt,
            fontSize = 11.sp,
            letterSpacing = 1.2.sp,
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(36.dp))
    }

    if (settingsOpen) {
        SettingsSheet(
            ui = ui,
            onDismiss = { settingsOpen = false },
            onLogout = { settingsOpen = false; onLogout() },
            onSetApiBase = onSetApiBase,
        )
    }
}

// ----------------------------------------------------------------------------
//  CARDS
// ----------------------------------------------------------------------------

@Composable
private fun ConnectionCard(ui: UiState, onConnect: () -> Unit, onDisconnect: () -> Unit) {
    Surface(
        color = MaterialTheme.colorScheme.surface,
        shape = RoundedCornerShape(4.dp),
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, ZT_Line, RoundedCornerShape(4.dp)),
    ) {
        Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(20.dp)) {

            Row(verticalAlignment = Alignment.CenterVertically) {
                val (dotColor, label) = when (ui.tunnel) {
                    ConnState.Connected     -> ZT_Moss to "Connected"
                    ConnState.Connecting    -> ZT_Amber to "Connecting…"
                    ConnState.Disconnecting -> ZT_Amber to "Disconnecting…"
                    ConnState.Failed        -> ZT_Terra to "Failed"
                    ConnState.Disconnected  -> ZT_InkFnt to "Disconnected"
                }
                Box(
                    Modifier
                        .size(14.dp)
                        .clip(RoundedCornerShape(50))
                        .background(dotColor),
                )
                Spacer(Modifier.width(12.dp))
                Text(label, fontSize = 22.sp, fontFamily = FontFamily.Serif, color = ZT_Ink)
            }

            if (ui.statusLine.isNotBlank()) {
                Text(ui.statusLine, color = ZT_InkDim, fontSize = 13.sp)
            }

            val isOn = ui.tunnel == ConnState.Connected
            val isBusy = ui.tunnel == ConnState.Connecting || ui.tunnel == ConnState.Disconnecting

            Button(
                onClick = { if (isOn) onDisconnect() else onConnect() },
                enabled = !isBusy,
                modifier = Modifier.fillMaxWidth().height(56.dp),
                shape = RoundedCornerShape(2.dp),
                colors = if (isOn)
                    ButtonDefaults.buttonColors(containerColor = ZT_Terra, contentColor = ZT_Ink)
                else ButtonDefaults.buttonColors(),
            ) {
                Text(
                    if (isOn) "Disconnect" else "Connect",
                    letterSpacing = 1.4.sp,
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun RoutingCard(
    ui: UiState,
    onSelectEntry: (String) -> Unit,
    onSelectExit: (String?) -> Unit,
) {
    Surface(
        color = MaterialTheme.colorScheme.surface,
        shape = RoundedCornerShape(4.dp),
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, ZT_Line, RoundedCornerShape(4.dp)),
    ) {
        Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {

            Text(
                "ROUTING",
                style = MaterialTheme.typography.labelSmall,
                color = ZT_InkFnt,
                letterSpacing = 2.sp,
            )

            RegionDropdown(
                label = "Entry node",
                value = ui.entryRegion,
                regions = ui.regions,
                onSelect = onSelectEntry,
            )

            val multihop = ui.exitRegion != null
            Row(verticalAlignment = Alignment.CenterVertically) {
                Switch(
                    checked = multihop,
                    onCheckedChange = { on ->
                        if (on) {
                            // Default exit = first region that isn't the entry
                            val firstDifferent = ui.regions.firstOrNull { it.code != ui.entryRegion }
                            onSelectExit(firstDifferent?.code ?: ui.entryRegion)
                        } else {
                            onSelectExit(null)
                        }
                    },
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = ZT_Amber,
                        checkedTrackColor = ZT_BgElev,
                        checkedBorderColor = ZT_Amber,
                    ),
                )
                Spacer(Modifier.width(12.dp))
                Column {
                    Text("Multi-hop", color = ZT_Ink, fontSize = 15.sp)
                    Text(
                        if (multihop) "Traffic enters one country, exits another"
                        else "Single-hop — your tunnel terminates at the entry node",
                        color = ZT_InkFnt,
                        fontSize = 12.sp,
                    )
                }
            }

            // A single-VPS test deployment answers to all three region codes
            // from one machine. The route is real and worth testing; the
            // privacy property is not there, and saying "enters one country,
            // exits another" over the top of it would be a plain lie.
            if (multihop && ui.sameHostRoute) {
                Row(
                    Modifier
                        .fillMaxWidth()
                        .border(1.dp, ZT_Terra, RoundedCornerShape(3.dp))
                        .padding(12.dp),
                ) {
                    Text(
                        "Entry and exit resolved to the SAME host — this control " +
                        "plane is a test deployment. Routing works; nothing is hidden.",
                        color = ZT_Ink, fontSize = 12.sp,
                    )
                }
            }

            if (multihop) {
                RegionDropdown(
                    label = "Exit node",
                    value = ui.exitRegion ?: "",
                    regions = ui.regions.filter { it.code != ui.entryRegion },
                    onSelect = onSelectExit,
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun RegionDropdown(
    label: String,
    value: String,
    regions: List<Region>,
    onSelect: (String) -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }
    val current = regions.firstOrNull { it.code == value }

    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { expanded = it },
        modifier = Modifier.fillMaxWidth(),
    ) {
        OutlinedTextField(
            value = "${value.uppercase()}  ${current?.name ?: "—"}",
            onValueChange = {},
            readOnly = true,
            label = { Text(label) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier
                .fillMaxWidth()
                .menuAnchor(),
        )
        ExposedDropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false },
        ) {
            regions.forEach { r ->
                DropdownMenuItem(
                    text = { Text("${r.code.uppercase()}  ${r.name}") },
                    onClick = { onSelect(r.code); expanded = false },
                )
            }
        }
    }
}

@Composable
private fun AccountCard(ui: UiState) {
    val acct = ui.account ?: return
    Surface(
        color = MaterialTheme.colorScheme.surface,
        shape = RoundedCornerShape(4.dp),
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, ZT_Line, RoundedCornerShape(4.dp)),
    ) {
        Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("ACCOUNT", style = MaterialTheme.typography.labelSmall, color = ZT_InkFnt)
            kv("Token", acct.token.take(4) + "-****-****-" + acct.token.takeLast(4))
            kv("Subscription", acct.mode)
            kv("Expires in", "${acct.daysRemaining} " +
                if (acct.daysRemaining == 1) "day" else "days")
            // The cap is per-plan: a trial account gets fewer devices than a
            // paid one. Printing a constant "8" told trial customers a number
            // the API would then refuse to honour.
            kv("Devices", if (acct.maxDevices > 0)
                              "${acct.deviceCount} / ${acct.maxDevices}"
                          else "${acct.deviceCount}")
        }
    }
}

@Composable
private fun kv(k: String, v: String) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Text(k, color = ZT_InkDim, fontSize = 13.sp)
        Spacer(Modifier.weight(1f))
        Text(v, color = ZT_Ink, fontFamily = FontFamily.Monospace, fontSize = 13.sp)
    }
}

// ----------------------------------------------------------------------------
//  Devices
// ----------------------------------------------------------------------------

/**
 * The registered devices, and a way to remove one.
 *
 * Without this the device cap is a dead end. Registration is capped, the app
 * had no list and no delete, and a customer who had used their slots from
 * other machines got a 403 with no way to act on it from the phone in their
 * hand. The desktop client has had `0trust devices` and `0trust remove` from
 * the start; this is the same thing.
 */
@Composable
private fun DevicesCard(
    ui: UiState,
    onRefresh: () -> Unit,
    onRemove: (String) -> Unit,
) {
    var confirming by remember { mutableStateOf<Device?>(null) }

    Surface(
        color = MaterialTheme.colorScheme.surface,
        shape = RoundedCornerShape(4.dp),
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, ZT_Line, RoundedCornerShape(4.dp)),
    ) {
        Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("DEVICES", style = MaterialTheme.typography.labelSmall, color = ZT_InkFnt)
                Spacer(Modifier.weight(1f))
                if (ui.devicesLoading) {
                    CircularProgressIndicator(
                        color = ZT_InkFnt, strokeWidth = 2.dp,
                        modifier = Modifier.size(16.dp),
                    )
                } else {
                    TextButton(onClick = onRefresh, contentPadding = PaddingValues(0.dp)) {
                        Text("Refresh", color = ZT_Amber, fontSize = 12.sp)
                    }
                }
            }

            if (ui.devices.isEmpty() && !ui.devicesLoading) {
                Text(
                    "No devices registered yet. Connecting from this phone registers it.",
                    color = ZT_InkFnt, fontSize = 12.sp,
                )
            }

            ui.devices.forEach { d ->
                val isThis = d.pubkey == ui.thisDevicePubkey
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(
                            if (isThis) "${d.name}  (this phone)" else d.name.ifBlank { "unnamed" },
                            color = ZT_Ink, fontSize = 14.sp,
                        )
                        Text(
                            buildString {
                                append(d.meshIp)
                                if (d.multihop && d.entryNode != null && d.exitNode != null) {
                                    append("  ·  ${d.entryNode} → ${d.exitNode}")
                                }
                            },
                            color = ZT_InkFnt, fontSize = 11.sp,
                            fontFamily = FontFamily.Monospace,
                        )
                    }
                    // Removing this phone's own registration mid-session would
                    // drop the tunnel and leave the UI claiming it was up.
                    // Sign out does that deliberately; this button should not
                    // do it by accident.
                    IconButton(
                        onClick = { confirming = d },
                        enabled = !isThis || ui.tunnel == ConnState.Disconnected,
                    ) {
                        Icon(
                            Icons.Outlined.Delete,
                            contentDescription = "Remove ${d.name}",
                            tint = if (isThis && ui.tunnel != ConnState.Disconnected)
                                       ZT_InkFnt else ZT_Terra,
                        )
                    }
                }
            }
        }
    }

    confirming?.let { d ->
        AlertDialog(
            onDismissRequest = { confirming = null },
            containerColor = ZT_BgElev,
            title = { Text("Remove this device?", color = ZT_Ink) },
            text = {
                Text(
                    "${d.name.ifBlank { "This device" }} will lose its tunnel and free " +
                    "a slot on your account. It can register again at any time.",
                    color = ZT_InkDim,
                )
            },
            confirmButton = {
                TextButton(onClick = { onRemove(d.pubkey); confirming = null }) {
                    Text("Remove", color = ZT_Terra)
                }
            },
            dismissButton = {
                TextButton(onClick = { confirming = null }) {
                    Text("Cancel", color = ZT_InkDim)
                }
            },
        )
    }
}

@Composable
private fun ErrorBanner(message: String, onDismiss: () -> Unit) {
    Surface(
        color = ZT_BgElev,
        shape = RoundedCornerShape(4.dp),
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, ZT_Terra, RoundedCornerShape(4.dp)),
    ) {
        Row(
            Modifier.padding(start = 16.dp, top = 12.dp, bottom = 12.dp, end = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(message, color = ZT_Ink, fontSize = 13.sp, modifier = Modifier.weight(1f))
            IconButton(onClick = onDismiss) {
                Icon(Icons.Outlined.Close, contentDescription = "Dismiss", tint = ZT_InkDim)
            }
        }
    }
}

// ----------------------------------------------------------------------------
//  Settings sheet
// ----------------------------------------------------------------------------

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SettingsSheet(
    ui: UiState,
    onDismiss: () -> Unit,
    onLogout: () -> Unit,
    onSetApiBase: (String) -> Unit,
) {
    val ctx = LocalContext.current
    var autoConnect by remember {
        mutableStateOf(
            AppState.encryptedPrefs(ctx)
                .getBoolean(TunnelBootstrap.KEY_AUTO_CONNECT, false)
        )
    }
    var apiBase by remember(ui.apiBase) { mutableStateOf(ui.apiBase) }

    ModalBottomSheet(onDismissRequest = onDismiss, containerColor = ZT_BgElev) {
        Column(
            Modifier
                .padding(24.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text("Settings", style = MaterialTheme.typography.headlineMedium, color = ZT_Ink)

            Row(verticalAlignment = Alignment.CenterVertically) {
                Switch(
                    checked = autoConnect,
                    onCheckedChange = {
                        autoConnect = it
                        AppState.encryptedPrefs(ctx).edit()
                            .putBoolean(TunnelBootstrap.KEY_AUTO_CONNECT, it).apply()
                    },
                )
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f)) {
                    Text("Reconnect after restart", color = ZT_Ink)
                    Text(
                        "Brings the tunnel back up when the phone boots. Android can " +
                        "delay or skip this; Always-on VPN below is the reliable version.",
                        color = ZT_InkFnt, fontSize = 12.sp,
                    )
                }
            }

            // Always-on + block-without-VPN is the system's own kill switch,
            // and it is stronger than anything an app can do for itself. We
            // cannot toggle it from here — only the user can, in Settings —
            // so the honest thing is to say so and open the right screen.
            Column(Modifier.fillMaxWidth()) {
                Text("Always-on VPN", color = ZT_Ink)
                Text(
                    "Android can hold the tunnel open and block traffic whenever it " +
                    "is down — a kill switch the app cannot be talked out of. It has " +
                    "to be switched on in system settings.",
                    color = ZT_InkFnt, fontSize = 12.sp,
                )
                Spacer(Modifier.height(8.dp))
                TextButton(
                    onClick = {
                        runCatching {
                            ctx.startActivity(
                                Intent(Settings.ACTION_VPN_SETTINGS)
                                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                            )
                        }
                    },
                    contentPadding = PaddingValues(0.dp),
                ) {
                    Text("Open VPN settings", color = ZT_Amber)
                }
            }

            HorizontalDivider(color = ZT_Line)

            // build.gradle.kts has always said a self-hosted deployment could
            // be pointed at from here. The preference was read on every start
            // and there was nothing anywhere that could write it.
            Column(Modifier.fillMaxWidth()) {
                Text("Control plane", color = ZT_Ink)
                Text(
                    "Leave this alone unless you run your own 0trust deployment. " +
                    "HTTPS only — the account token is a bearer credential.",
                    color = ZT_InkFnt, fontSize = 12.sp,
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = apiBase,
                    onValueChange = { apiBase = it },
                    singleLine = true,
                    label = { Text("Address") },
                    placeholder = { Text(BuildConfig.DEFAULT_API_BASE) },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(8.dp))
                Row {
                    TextButton(
                        onClick = { onSetApiBase(apiBase) },
                        enabled = apiBase.trim().trimEnd('/') != ui.apiBase,
                    ) {
                        Text("Save", color = ZT_Amber)
                    }
                    TextButton(onClick = {
                        apiBase = BuildConfig.DEFAULT_API_BASE
                        onSetApiBase("")
                    }) {
                        Text("Reset", color = ZT_InkDim)
                    }
                }
            }

            HorizontalDivider(color = ZT_Line)

            TextButton(onClick = onLogout) {
                Text("Sign out", color = ZT_Terra)
            }
            Text(
                "Signing out stops the tunnel and forgets the token and this " +
                "device's key. There is no recovery — keep your token.",
                color = ZT_InkFnt, fontSize = 12.sp,
            )

            Spacer(Modifier.height(24.dp))
            Text(
                "0trust VPN  ·  v${BuildConfig.VERSION_NAME}",
                fontSize = 11.sp,
                color = ZT_InkFnt,
            )
            Spacer(Modifier.height(24.dp))
        }
    }
}

// ----------------------------------------------------------------------------
//  Brand mark
// ----------------------------------------------------------------------------

@Composable
private fun Brand() {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(
            "0",
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.Bold,
            fontSize = 36.sp,
            color = ZT_Amber,
        )
        Text(
            "trustvpn",
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.Bold,
            fontSize = 22.sp,
            color = ZT_Ink,
            modifier = Modifier.padding(start = 2.dp, bottom = 4.dp),
        )
    }
}
