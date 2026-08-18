//
// APIClient.swift
// HTTP client for the 0trust control plane.
//

import Foundation

enum APIError: Error {
    case notLoggedIn
    case appGroupMissing
    case http(Int, String)
}

struct StatusResponse: Decodable {
    let status: String
    let expiresAt: Int
    let daysRemaining: Int
    let deviceCount: Int

    enum CodingKeys: String, CodingKey {
        case status
        case expiresAt = "expires_at"
        case daysRemaining = "days_remaining"
        case deviceCount = "device_count"
    }
}

struct Peer: Decodable {
    let publicKey: String
    let endpoint: String
    let allowedIPs: [String]
    let persistentKeepalive: Int

    enum CodingKeys: String, CodingKey {
        case publicKey = "public_key"
        case endpoint
        case allowedIPs = "allowed_ips"
        case persistentKeepalive = "persistent_keepalive"
    }
}

struct RegisterResponse: Decodable {
    let interfaceIP: String
    let dns: [String]
    let peers: [Peer]
    let multihop: Bool
    let entryNode: String?
    let exitNode: String?
    let expiresAt: Int?

    // Locally-generated, not from server:
    var privateKey: String = ""

    enum CodingKeys: String, CodingKey {
        case interfaceIP = "interface_ip"
        case dns
        case peers
        case multihop
        case entryNode = "entry_node"
        case exitNode = "exit_node"
        case expiresAt = "expires_at"
    }
}

final class APIClient {
    private let base: URL

    init(base: URL = URL(string: "https://0trustvpn.com")!) {
        self.base = base
    }

    func status(token: String) async throws -> StatusResponse {
        try await get("/api/v1/account/status", token: token)
    }

    func register(token: String, region: String, exitRegion: String?) async throws -> RegisterResponse {
        // Generate WireGuard keypair locally — private key never leaves the device.
        let (priv, pub) = try WGKeygen.generate()

        var body: [String: Any] = [
            "pubkey": pub,
            "device_name": UIDevice.current.name,
            "region": region,
        ]
        if let exitRegion { body["exit_region"] = exitRegion }

        var resp: RegisterResponse = try await post("/api/v1/wg/register",
                                                    token: token, body: body)
        resp.privateKey = priv
        return resp
    }

    // MARK: - HTTP helpers

    private func get<T: Decodable>(_ path: String, token: String) async throws -> T {
        var req = URLRequest(url: base.appendingPathComponent(path))
        req.addValue(token, forHTTPHeaderField: "X-Account-Token")
        let (data, resp) = try await URLSession.shared.data(for: req)
        try Self.checkStatus(resp, data: data)
        return try JSONDecoder().decode(T.self, from: data)
    }

    private func post<T: Decodable>(_ path: String, token: String, body: [String: Any]) async throws -> T {
        var req = URLRequest(url: base.appendingPathComponent(path))
        req.httpMethod = "POST"
        req.addValue(token, forHTTPHeaderField: "X-Account-Token")
        req.addValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, resp) = try await URLSession.shared.data(for: req)
        try Self.checkStatus(resp, data: data)
        return try JSONDecoder().decode(T.self, from: data)
    }

    private static func checkStatus(_ resp: URLResponse, data: Data) throws {
        guard let http = resp as? HTTPURLResponse else { return }
        if !(200..<300).contains(http.statusCode) {
            let msg = String(data: data, encoding: .utf8) ?? ""
            throw APIError.http(http.statusCode, msg)
        }
    }
}

// MARK: - WireGuard key generation
//
// In production, use WireGuardKit's Curve25519 wrapper:
//   import WireGuardKitC
//   let priv = Curve25519.KeyAgreement.PrivateKey()
//
// This skeleton sketches the shape; replace with WireGuardKit when integrating.
enum WGKeygen {
    static func generate() throws -> (priv: String, pub: String) {
        // Placeholder — see comment above.
        // Real implementation: WireGuardKit.PrivateKey() then .publicKey
        fatalError("Implement using WireGuardKit's key generation")
    }
}

#if canImport(UIKit)
import UIKit
#endif
