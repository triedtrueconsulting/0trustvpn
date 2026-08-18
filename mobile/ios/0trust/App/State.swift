//
// State.swift
// App-wide state. Persists the account token in the keychain (TODO: keychain
// wrapper not included in this skeleton; use KeychainAccess or equivalent).
//

import Foundation
import NetworkExtension

@MainActor
class AppState: ObservableObject {
    @Published var token: String = ""           // keychain-backed in production
    @Published var loggedIn: Bool = false
    @Published var tunnelStatus: NEVPNStatus = .invalid
    @Published var entryRegion: String = "zur"
    @Published var exitRegion: String = ""      // empty = single-hop
    @Published var subscriptionStatus: String = ""
    @Published var daysRemaining: Int = 0

    private let api = APIClient()
    private var tunnelManager: NETunnelProviderManager?

    init() {
        Task { await loadTunnel() }
    }

    func login(token: String) async throws {
        // Validate against server
        try await api.status(token: token)
        self.token = token
        self.loggedIn = true
        // TODO: persist token to keychain
    }

    func logout() async {
        await disconnect()
        token = ""
        loggedIn = false
    }

    func refresh() async {
        guard loggedIn else { return }
        do {
            let s = try await api.status(token: token)
            self.subscriptionStatus = s.status
            self.daysRemaining = s.daysRemaining
        } catch {
            print("status refresh failed: \(error)")
        }
    }

    // MARK: - Tunnel control

    private func loadTunnel() async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            tunnelManager = managers.first ?? NETunnelProviderManager()
            tunnelStatus = tunnelManager?.connection.status ?? .invalid
        } catch {
            print("loadTunnel: \(error)")
        }
    }

    func connect() async throws {
        guard loggedIn else { throw APIError.notLoggedIn }
        let reg = try await api.register(
            token: token, region: entryRegion, exitRegion: exitRegion.isEmpty ? nil : exitRegion
        )
        // Build wg-quick-compatible config string and stash it for the
        // tunnel extension to read via App Group shared UserDefaults.
        let config = WGConfig.serialize(privateKey: reg.privateKey,
                                         interfaceIP: reg.interfaceIP,
                                         dns: reg.dns,
                                         peers: reg.peers)
        try saveSharedConfig(config)
        try await ensureTunnel()
        try tunnelManager?.connection.startVPNTunnel()
    }

    func disconnect() async {
        tunnelManager?.connection.stopVPNTunnel()
    }

    private func ensureTunnel() async throws {
        let mgr = tunnelManager ?? NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = "vpn.zerotrust.app.tunnel"
        proto.serverAddress = "0trust mesh"  // shown in Settings → VPN
        mgr.protocolConfiguration = proto
        mgr.localizedDescription = "0trust VPN"
        mgr.isEnabled = true
        try await mgr.saveToPreferences()
        try await mgr.loadFromPreferences()
        tunnelManager = mgr
    }

    private func saveSharedConfig(_ config: String) throws {
        guard let defaults = UserDefaults(suiteName: "group.vpn.zerotrust.app") else {
            throw APIError.appGroupMissing
        }
        defaults.set(config, forKey: "wg.config")
    }
}

// Minimal wg-quick serializer (same format the desktop CLI writes).
enum WGConfig {
    static func serialize(privateKey: String, interfaceIP: String,
                          dns: [String], peers: [Peer]) -> String {
        var s = "[Interface]\n"
        s += "PrivateKey = \(privateKey)\n"
        s += "Address = \(interfaceIP)\n"
        if !dns.isEmpty { s += "DNS = \(dns.joined(separator: ", "))\n" }
        s += "\n"
        for p in peers {
            s += "[Peer]\n"
            s += "PublicKey = \(p.publicKey)\n"
            s += "Endpoint = \(p.endpoint)\n"
            s += "AllowedIPs = \(p.allowedIPs.joined(separator: ", "))\n"
            if p.persistentKeepalive > 0 {
                s += "PersistentKeepalive = \(p.persistentKeepalive)\n"
            }
            s += "\n"
        }
        return s
    }
}
