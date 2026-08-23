package vpn.zerotrust.app

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
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
)

@Serializable data class AccountStatusResponse(
    val status: String,
    @SerialName("expires_at")     val expiresAt: Long? = null,
    @SerialName("days_remaining") val daysRemaining: Int? = null,
    @SerialName("device_count")   val deviceCount: Int,
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
        )
    }

    /** GET /api/v1/regions */
    fun regions(): Result<List<Region>> = runCatching {
        val raw = get("/api/v1/regions")
        json.decodeFromString<RegionListResponse>(raw)
            .regions.map { Region(it.code, it.name) }
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
