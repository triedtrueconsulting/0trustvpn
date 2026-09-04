//
// WgConfig.swift
// Turns a /wg/register response into a wg-quick config.
//
// Same output as the Go CLI's BuildConfig and the Android app's WgConfig, so
// all three clients hand WireGuard identical text for identical input. The
// tunnel extension parses it back with WireGuardKit's
// TunnelConfiguration(fromWgQuickConfig:).
//

import Foundation

struct WgConfig {
    let privateKey: String
    let interfaceIP: String
    /// nil when the exit node has no working IPv6 egress. See below.
    let interfaceIP6: String?
    let dns: [String]
    let peers: [WgPeer]

    /// Exactly one peer per config, never a list.
    ///
    /// WireGuard's AllowedIPs is a routing table, not a preference order: a
    /// second peer claiming 0.0.0.0/0 takes that prefix away from the first.
    /// Handing a client three "for failover" leaves one working peer, two
    /// inert ones, and the customer's key sitting in three nodes' manifests.
    /// Failover is the client reconnecting, not a longer peer list.
    var primaryPeer: WgPeer? { peers.first }

    func serialize() -> String {
        var s = "[Interface]\n"
        s += "PrivateKey = \(privateKey)\n"
        // Both families on one Address line when the exit carries v6.
        let addresses = [interfaceIP, interfaceIP6].compactMap { $0 }
            .filter { !$0.isEmpty }
        s += "Address = \(addresses.joined(separator: ", "))\n"
        if !dns.isEmpty {
            s += "DNS = \(dns.joined(separator: ", "))\n"
        }

        guard let p = primaryPeer else { return s }
        s += "\n[Peer]\n"
        s += "PublicKey = \(p.publicKey)\n"
        s += "Endpoint = \(p.endpoint)\n"
        // The server always claims both default routes. If it somehow sends
        // none, claim them here rather than leaving the tunnel with no routes
        // at all — a tunnel that carries nothing while reporting success is
        // the failure mode this product cannot have.
        let allowed = p.allowedIPs.isEmpty ? ["0.0.0.0/0", "::/0"] : p.allowedIPs
        s += "AllowedIPs = \(allowed.joined(separator: ", "))\n"
        if let ka = p.persistentKeepalive, ka > 0 {
            s += "PersistentKeepalive = \(ka)\n"
        }
        return s
    }
}

/// The handoff between the app and the tunnel extension.
///
/// They are separate processes: iOS starts the extension on demand, including
/// after a reboot with Always-on VPN, when the app is not running at all. The
/// config therefore has to be somewhere the extension can read by itself,
/// which is the shared App Group container.
///
/// The config contains the device's PRIVATE key, so it is written with
/// .completeUntilFirstUserAuthentication rather than left at the default —
/// the extension may need it while the screen is locked.
enum SharedStore {
    static let appGroup = "group.vpn.zerotrust.app"
    private static let configName = "wg.conf"

    static var containerURL: URL? {
        FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: appGroup)
    }

    static func writeConfig(_ text: String) throws {
        guard let dir = containerURL else { throw SharedStoreError.noAppGroup }
        let url = dir.appendingPathComponent(configName)
        try text.data(using: .utf8)?.write(
            to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }

    static func readConfig() throws -> String {
        guard let dir = containerURL else { throw SharedStoreError.noAppGroup }
        let url = dir.appendingPathComponent(configName)
        guard let data = FileManager.default.contents(atPath: url.path),
              let text = String(data: data, encoding: .utf8) else {
            throw SharedStoreError.noConfig
        }
        return text
    }

    static func clearConfig() {
        guard let dir = containerURL else { return }
        try? FileManager.default.removeItem(
            at: dir.appendingPathComponent(configName))
    }
}

enum SharedStoreError: Error, LocalizedError {
    case noAppGroup
    case noConfig

    var errorDescription: String? {
        switch self {
        case .noAppGroup:
            return "App Group container unavailable — check the entitlements on both targets."
        case .noConfig:
            return "No tunnel configuration has been written yet."
        }
    }
}
