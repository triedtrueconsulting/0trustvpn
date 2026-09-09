//
// APIClient.swift
// The 0trust control-plane client.
//
// client/internal/api/api.go is the CANONICAL wire contract and this file
// must match it field for field. Two rules that have broken a client here
// before:
//
//   - The wire is snake_case. Every property below carries an explicit
//     CodingKey rather than relying on a decoder strategy, so the mapping is
//     visible at the point a reviewer reads the field. The Android client was
//     once entirely broken by a camelCase/snake_case mismatch.
//   - Auth is the `X-Account-Token` header. Never `Authorization: Bearer` —
//     the token IS the credential, there is no OAuth anywhere in this product.
//

import Foundation

enum APIError: Error, LocalizedError {
    case notLoggedIn
    case http(status: Int, body: String)
    case transport(Error)
    case badURL(String)

    var errorDescription: String? {
        switch self {
        case .notLoggedIn:
            return "Not signed in."
        case .http(let status, let body):
            switch status {
            case 401: return "That token was not recognised."
            case 402: return "This subscription is not active. Top it up to reconnect."
            case 403: return "This account has been suspended."
            case 409: return "Device limit reached — remove a device to add this one."
            case 503: return "No mesh node is available right now. Try again shortly."
            default:  return body.isEmpty ? "Server error \(status)." : body
            }
        case .transport(let e):
            return "Could not reach the control plane: \(e.localizedDescription)"
        case .badURL(let u):
            return "That control-plane address cannot be used: \(u)"
        }
    }
}

// MARK: - Wire types

struct AccountStatus: Decodable {
    let status: String
    let expiresAt: Int64?
    let daysRemaining: Int?
    let plan: String?
    /// The device cap for THIS account's plan — 2 on a trial, 8 paid. Always
    /// render this rather than a constant: printing a hardcoded 8 told trial
    /// customers they had six slots spare until the next register returned
    /// 409. That shipped on three separate surfaces before it was caught.
    let maxDevices: Int?
    let deviceCount: Int?

    enum CodingKeys: String, CodingKey {
        case status
        case expiresAt     = "expires_at"
        case daysRemaining = "days_remaining"
        case plan
        case maxDevices    = "max_devices"
        case deviceCount   = "device_count"
    }
}

struct WgPeer: Decodable {
    let publicKey: String
    let endpoint: String
    let allowedIPs: [String]
    let persistentKeepalive: Int?

    enum CodingKeys: String, CodingKey {
        case publicKey           = "public_key"
        case endpoint
        case allowedIPs          = "allowed_ips"
        case persistentKeepalive = "persistent_keepalive"
    }
}

struct RegisterResponse: Decodable {
    let interfaceIP: String
    /// Set only when the exit node has working IPv6 egress. Empty means v6
    /// stays blackholed by the ::/0 in AllowedIPs — which is the point. The
    /// tunnel always CLAIMS v6 so it cannot leak around us, and only carries
    /// it where there is somewhere for it to go. Never drop ::/0 to "fix"
    /// v6: without an address it is blackholed, which is the safe failure.
    let interfaceIP6: String?
    let dns: [String]
    let peers: [WgPeer]
    let multihop: Bool?
    let entryNode: String?
    let exitNode: String?
    /// Entry and exit resolved to the same machine — a single-VPS test
    /// deployment. The route is real; the privacy property multi-hop exists
    /// for is not, and the app says so rather than repeating the usual claim.
    let sameHost: Bool?

    enum CodingKeys: String, CodingKey {
        case interfaceIP  = "interface_ip"
        case interfaceIP6 = "interface_ip6"
        case dns
        case peers
        case multihop
        case entryNode    = "entry_node"
        case exitNode     = "exit_node"
        case sameHost     = "same_host"
    }
}

struct DeviceInfo: Decodable, Identifiable {
    let pubkey: String
    let deviceName: String?
    let meshIP: String?
    let createdAt: Int64?
    let lastSeen: Int64?
    let multihop: Bool?
    let entryNode: String?
    let exitNode: String?

    var id: String { pubkey }

    enum CodingKeys: String, CodingKey {
        case pubkey
        case deviceName = "device_name"
        case meshIP     = "mesh_ip"
        case createdAt  = "created_at"
        case lastSeen   = "last_seen"
        case multihop
        case entryNode  = "entry_node"
        case exitNode   = "exit_node"
    }
}

/// A message waiting for this account. There is no email address on file —
/// that is the product — so this is the only channel the service has, and the
/// only warning a customer gets before a subscription ends.
struct NoticeInfo: Decodable, Identifiable {
    let id: Int
    let severity: String
    let subject: String
    let body: String
    let createdAt: Int64?

    enum CodingKeys: String, CodingKey {
        case id, severity, subject, body
        case createdAt = "created_at"
    }
}

struct RegionInfo: Decodable, Identifiable {
    let code: String
    let name: String?
    var id: String { code }
}

/// /api/v1/regions answers with an envelope — {"regions": [...]} — not a bare
/// array. Decoding the array directly fails and leaves the picker empty with
/// no visible error, which is how this was found.
struct RegionsResponse: Decodable {
    let regions: [RegionInfo]
}

/// What the offer actually is. Rendered, never hardcoded: the trial length is
/// an operator setting, and a number compiled into an App Store build cannot
/// be corrected without shipping a new release through review.
struct PublicConfig: Decodable {
    struct Trial: Decodable {
        let enabled: Bool?
        let days: Int?
        let label: String?
        let maxDevices: Int?
        enum CodingKeys: String, CodingKey {
            case enabled, days, label
            case maxDevices = "max_devices"
        }
    }
    let trial: Trial?
    let maxDevices: Int?
    enum CodingKeys: String, CodingKey {
        case trial
        case maxDevices = "max_devices"
    }
}

// MARK: - Client

actor APIClient {
    static let defaultBase = URL(string: "https://0trustvpn.com")!

    private let base: URL
    private let session: URLSession

    init(base: URL = APIClient.defaultBase) {
        self.base = base
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 20
        cfg.httpAdditionalHeaders = ["Accept": "application/json"]
        // The control plane is the one host this app talks to and it is
        // reached over TLS. Nothing here should ever be cached to disk.
        cfg.urlCache = nil
        self.session = URLSession(configuration: cfg)
    }

    // MARK: Calls

    func status(token: String) async throws -> AccountStatus {
        try await send("GET", "/api/v1/account/status", token: token)
    }

    func regions() async throws -> [RegionInfo] {
        let envelope: RegionsResponse =
            try await send("GET", "/api/v1/regions", token: nil)
        return envelope.regions
    }

    func config() async throws -> PublicConfig {
        try await send("GET", "/api/v1/config", token: nil)
    }

    func notices(token: String) async throws -> [NoticeInfo] {
        try await send("GET", "/api/v1/notices", token: token)
    }

    func markNoticeRead(token: String, id: Int) async throws {
        _ = try await sendNoContent("POST", "/api/v1/notices/\(id)/read",
                                    token: token)
    }

    func devices(token: String) async throws -> [DeviceInfo] {
        try await send("GET", "/api/v1/devices", token: token)
    }

    func deleteDevice(token: String, pubkey: String) async throws {
        // WireGuard public keys are standard base64 and routinely contain
        // '/' and '+', so the key has to be percent-escaped rather than
        // pasted into the path.
        let escaped = pubkey.addingPercentEncoding(
            withAllowedCharacters: .alphanumerics) ?? pubkey
        _ = try await sendNoContent("DELETE", "/api/v1/devices/\(escaped)", token: token)
    }

    func register(token: String, pubkey: String, deviceName: String,
                  region: String, exitRegion: String?) async throws -> RegisterResponse {
        var body: [String: Any] = [
            "pubkey": pubkey,
            "device_name": deviceName,
            "region": region,
        ]
        if let exitRegion, !exitRegion.isEmpty { body["exit_region"] = exitRegion }
        return try await send("POST", "/api/v1/wg/register", token: token, body: body)
    }

    func rotate(token: String, pubkey: String,
                region: String, exitRegion: String?) async throws -> RegisterResponse {
        var body: [String: Any] = ["pubkey": pubkey, "region": region]
        if let exitRegion, !exitRegion.isEmpty { body["exit_region"] = exitRegion }
        return try await send("POST", "/api/v1/wg/rotate", token: token, body: body)
    }

    // MARK: Transport

    /// The base with any trailing "/" removed, so joining a path that starts
    /// with "/" cannot produce a double slash. A configured base of
    /// "https://0trustvpn.com/" is an ordinary thing for someone to type.
    private var joinBase: String {
        var s = base.absoluteString
        while s.hasSuffix("/") { s.removeLast() }
        return s
    }

    private func request(_ method: String, _ path: String,
                         token: String?, body: [String: Any]?) throws -> URLRequest {
        // Concatenated, not appendingPathComponent.
        //
        // deleteDevice hands this a path whose last segment is ALREADY
        // percent-encoded — a WireGuard key is base64 and routinely contains
        // '/' and '+', and every one of them ends in '='. appendingPathComponent
        // escapes what it is given, so a '%3D' that reaches it can come back
        // out as '%253D' and the server matches no device: the delete 404s and
        // the customer cannot free a slot against an 8-device cap. Whether
        // Foundation re-escapes an existing sequence is a detail of CFURL that
        // this app should not be resting on either way, and nothing here has
        // ever been compiled, let alone run, so it would not be caught.
        //
        // The Android client concatenates for exactly this reason and says so
        // (ApiClient.kt, deleteDevice). One construction, one meaning, on both
        // platforms.
        guard let url = URL(string: joinBase + path) else {
            throw APIError.badURL(joinBase + path)
        }
        var req = URLRequest(url: url)
        req.httpMethod = method
        if let token, !token.isEmpty {
            req.setValue(token, forHTTPHeaderField: "X-Account-Token")
        }
        if let body {
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = try JSONSerialization.data(withJSONObject: body)
        }
        return req
    }

    private func send<T: Decodable>(_ method: String, _ path: String,
                                    token: String?, body: [String: Any]? = nil) async throws -> T {
        let data = try await sendNoContent(method, path, token: token, body: body)
        return try JSONDecoder().decode(T.self, from: data)
    }

    @discardableResult
    private func sendNoContent(_ method: String, _ path: String,
                               token: String?, body: [String: Any]? = nil) async throws -> Data {
        let req = try request(method, path, token: token, body: body)
        let data: Data, resp: URLResponse
        do {
            (data, resp) = try await session.data(for: req)
        } catch {
            throw APIError.transport(error)
        }
        if let http = resp as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
            throw APIError.http(status: http.statusCode,
                                body: String(data: data, encoding: .utf8) ?? "")
        }
        return data
    }
}
