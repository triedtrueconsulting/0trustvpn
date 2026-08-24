package vpn.zerotrust.app

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.net.URLEncoder
import java.util.concurrent.TimeUnit

// Wire types — these match the FastAPI models in api/main.py 1:1.
// The Python API uses snake_case JSON; we keep Kotlin-idiomatic camelCase
// property names by annotating each field with @SerialName.

@Serializable data class WgRegisterRequest(
    val pubkey: String,
    @SerialName("device_name") val deviceName: String,
    val region: String,
    @SerialName("exit_region") val exitRegion: String? = null,
)

@Serializable data class WgRotateRequest(
    val pubkey: String,
    val region: String,
    @SerialName("exit_region") val exitRegion: String? = null,
)

@Serializable data class WgPeer(
    val id: String = "",
    @SerialName("public_key")           val publicKey: String,
    val endpoint: String,
    @SerialName("allowed_ips")          val allowedIps: List<String> = emptyList(),
    @SerialName("persistent_keepalive") val persistentKeepalive: Int = 25,
)

@Serializable data class WgRegisterResponse(
    @SerialName("interface_ip") val interfaceIp: String,
    // Present only when the exit node has working IPv6 egress. Null means v6
    // is blackholed by the ::/0 AllowedIPs rather than carried — which is
    // deliberate, so v6 cannot leak around the tunnel on a dual-stack network.
    @SerialName("interface_ip6") val interfaceIp6: String? = null,
    val dns: List<String> = emptyList(),
    val peers: List<WgPeer> = emptyList(),
    val multihop: Boolean = false,
    @SerialName("entry_node") val entryNode: String? = null,
    @SerialName("exit_node")  val exitNode:  String? = null,
    @SerialName("expires_at") val expiresAt: Long? = null,
    // Set when the control plane resolved entry and exit to the same machine:
    // a single-VPS test deployment wearing three region codes. The route is
    // real, the privacy property multi-hop exists for is not, and the app has
    // to say so instead of printing the usual claim. The CLI already does.
    @SerialName("same_host")  val sameHost: Boolean = false,
)

@Serializable data class AccountStatusResponse(
    val status: String,
    @SerialName("expires_at")     val expiresAt: Long? = null,
    @SerialName("days_remaining") val daysRemaining: Int? = null,
    @SerialName("device_count")   val deviceCount: Int,
    // A trial account has a lower cap than a paid one. The app used to print
    // "/ 8" for everybody, which told a trial customer the wrong number and
    // then refused their third device.
    val plan: String = "paid",
    @SerialName("max_devices")    val maxDevices: Int = 0,
    val notices: Int = 0,
)

@Serializable data class DeviceInfoResponse(
    val pubkey: String,
    @SerialName("device_name") val deviceName: String = "",
    @SerialName("mesh_ip")     val meshIp: String = "",
    @SerialName("created_at")  val createdAt: Long = 0,
    @SerialName("last_seen")   val lastSeen: Long = 0,
    val multihop: Boolean = false,
    @SerialName("entry_node")  val entryNode: String? = null,
    @SerialName("exit_node")   val exitNode: String? = null,
)

@Serializable data class RegionListItem(val code: String, val name: String)
@Serializable data class RegionListResponse(val regions: List<RegionListItem>)

/**
 * Thin OkHttp + kotlinx.serialization client.
 *
 * Auth model: every authenticated request includes the account token via
 * the X-Account-Token header. There's no Bearer/OAuth — the token IS the
 * credential (by design; see audit pack §3).
 */
class ApiClient(private val baseUrl: String, private val token: String) {

    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
        .retryOnConnectionFailure(false)
        .build()

    private val json = Json {
        ignoreUnknownKeys = true
        coerceInputValues = true
        explicitNulls = false
    }

    /** GET /api/v1/account/status */
    fun accountStatus(): Result<Account> = runCatching {
        val raw = get("/api/v1/account/status")
        val r = json.decodeFromString<AccountStatusResponse>(raw)
        Account(
            token         = token,
            expiresAt     = r.expiresAt ?: 0L,
            daysRemaining = r.daysRemaining ?: 0,
            deviceCount   = r.deviceCount,
            mode          = r.status,
            plan          = r.plan,
            maxDevices    = r.maxDevices,
        )
    }

    /** GET /api/v1/regions */
    fun regions(): Result<List<Region>> = runCatching {
        val raw = get("/api/v1/regions")
        json.decodeFromString<RegionListResponse>(raw)
            .regions.map { Region(it.code, it.name) }
    }

    /** GET /api/v1/devices */
    fun devices(): Result<List<Device>> = runCatching {
        json.decodeFromString<List<DeviceInfoResponse>>(get("/api/v1/devices"))
            .map {
                Device(
                    pubkey    = it.pubkey,
                    name      = it.deviceName,
                    meshIp    = it.meshIp,
                    lastSeen  = it.lastSeen,
                    multihop  = it.multihop,
                    entryNode = it.entryNode,
                    exitNode  = it.exitNode,
                )
            }
    }

    /**
     * DELETE /api/v1/devices/{pubkey}
     *
     * WireGuard public keys are standard base64 and routinely contain '/' and
     * '+', so the key is percent-encoded rather than pasted into the path. The
     * API declares the segment as {pubkey:path} for the same reason.
     */
    fun deleteDevice(pubkey: String): Result<Unit> = runCatching {
        val encoded = URLEncoder.encode(pubkey, "UTF-8").replace("+", "%2B")
        val req = Request.Builder()
            .url(baseUrl + "/api/v1/devices/" + encoded)
            .header("X-Account-Token", token)
            .header("Accept", "application/json")
            .delete()
            .build()
        execute(req)
        Unit
    }

    /** POST /api/v1/wg/register */
    fun wgRegister(req: WgRegisterRequest): Result<WgRegisterResponse> = runCatching {
        val body = json.encodeToString(WgRegisterRequest.serializer(), req)
        json.decodeFromString(post("/api/v1/wg/register", body))
    }

    /** POST /api/v1/wg/rotate */
    fun wgRotate(req: WgRotateRequest): Result<WgRegisterResponse> = runCatching {
        val body = json.encodeToString(WgRotateRequest.serializer(), req)
        json.decodeFromString(post("/api/v1/wg/rotate", body))
    }

    // ----------------------------------------------------------------
    // HTTP plumbing
    // ----------------------------------------------------------------

    private fun get(path: String): String {
        val req = Request.Builder()
            .url(baseUrl + path)
            .header("X-Account-Token", token)
            .header("Accept", "application/json")
            .get()
            .build()
        return execute(req)
    }

    private fun post(path: String, body: String): String {
        val req = Request.Builder()
            .url(baseUrl + path)
            .header("X-Account-Token", token)
            .header("Accept", "application/json")
            .post(body.toRequestBody("application/json".toMediaType()))
            .build()
        return execute(req)
    }

    private fun execute(req: Request): String {
        client.newCall(req).execute().use { resp ->
            val body = resp.body?.string() ?: ""
            if (!resp.isSuccessful) {
                throw RuntimeException("HTTP ${resp.code}: ${body.take(200)}")
            }
            return body
        }
    }
}
