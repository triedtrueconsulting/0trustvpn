//
// AppState.swift
// Everything the UI observes, and the only place tunnel lifecycle is driven.
//

import Foundation
import NetworkExtension
import SwiftUI
import WireGuardKit

@MainActor
final class AppState: ObservableObject {

    // MARK: Published

    @Published private(set) var loggedIn = false
    @Published private(set) var maskedToken = ""
    @Published private(set) var status: AccountStatus?
    @Published private(set) var devices: [DeviceInfo] = []
    /// Messages from the service — the only channel this account has.
    @Published private(set) var notices: [NoticeInfo] = []
    @Published private(set) var regions: [RegionInfo] = []
    @Published private(set) var config: PublicConfig?
    @Published private(set) var tunnelStatus: NEVPNStatus = .invalid
    @Published private(set) var lastHandshake: Date?
    /// The control plane resolved entry and exit to the same machine — a
    /// single-VPS test deployment. The routing is real; the privacy property
    /// multi-hop exists for is not, and the app says so rather than repeating
    /// the usual claim.
    @Published private(set) var sameHost = false
    @Published var entryRegion = "zur"
    /// Empty means single-hop.
    @Published var exitRegion = ""
    @Published var error: String?
    @Published var busy = false

    /// The device cap for the signed-in plan. Never a constant — see
    /// AccountStatus.maxDevices.
    var deviceCap: Int { status?.maxDevices ?? config?.maxDevices ?? 0 }
    var isTrial: Bool { status?.plan == "trial" }
    var thisDevicePubkey: String? { DeviceIdentity.publicKeyBase64 }

    /// Multi-hop is only meaningful when entry and exit differ; the control
    /// plane rejects equal regions, so the UI must not offer the pairing.
    var isMultihop: Bool { !exitRegion.isEmpty && exitRegion != entryRegion }

    // MARK: Private

    private var token: String = ""
    private var api = APIClient()
    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?

    // MARK: Lifecycle

    init() {
        if let saved = Keychain.get(Keychain.tokenKey), !saved.isEmpty {
            token = saved
            maskedToken = Self.mask(saved)
            loggedIn = true
        }
        observeTunnel()
        Task {
            await loadTunnelManager()
            await refreshPublic()
            if loggedIn { await refreshAll() }
        }
    }

    deinit {
        if let statusObserver {
            NotificationCenter.default.removeObserver(statusObserver)
        }
    }

    private func observeTunnel() {
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange, object: nil, queue: .main
        ) { [weak self] note in
            guard let conn = note.object as? NEVPNConnection else { return }
            Task { @MainActor in
                self?.tunnelStatus = conn.status
                if conn.status == .connected { await self?.refreshHandshake() }
                if conn.status == .disconnected { self?.lastHandshake = nil }
            }
        }
    }

    // MARK: Session

    func signIn(token raw: String) async {
        let cleaned = raw.uppercased().trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleaned.isEmpty else { return }
        busy = true; defer { busy = false }
        do {
            let s = try await api.status(token: cleaned)
            try Keychain.set(cleaned, for: Keychain.tokenKey)
            token = cleaned
            maskedToken = Self.mask(cleaned)
            status = s
            loggedIn = true
            error = nil
            await refreshAll()
        } catch {
            self.error = (error as? APIError)?.errorDescription ?? error.localizedDescription
        }
    }

    /// Signing out tears the tunnel down first — leaving it up would keep
    /// routing traffic for an account the app no longer holds a token for.
    /// The device stays registered so signing back in on this phone reuses
    /// the same slot rather than consuming a second one.
    func signOut() async {
        await disconnect()
        try? await manager?.removeFromPreferences()
        SharedStore.clearConfig()
        Keychain.delete(Keychain.tokenKey)
        DeviceIdentity.forget()
        token = ""
        maskedToken = ""
        loggedIn = false
        status = nil
        devices = []
        notices = []
        lastHandshake = nil
        manager = nil
    }

    // MARK: Refresh

    func refreshPublic() async {
        config = try? await api.config()
        if let list = try? await api.regions(), !list.isEmpty {
            regions = list
            if !list.contains(where: { $0.code == entryRegion }) {
                entryRegion = list[0].code
            }
        }
    }

    func refreshAll() async {
        guard loggedIn else { return }
        // Hoist the token out of the actor-isolated property before the two
        // concurrent reads, so neither child task captures self.
        let tok = token
        async let s = try? await api.status(token: tok)
        async let d = try? await api.devices(token: tok)
        async let n = try? await api.notices(token: tok)
        status = await s
        devices = (await d) ?? []
        notices = (await n) ?? []
    }

    func refreshDevices() async {
        guard loggedIn else { return }
        devices = (try? await api.devices(token: token)) ?? []
    }

    func refreshNotices() async {
        guard loggedIn else { return }
        notices = (try? await api.notices(token: token)) ?? []
    }

    /// Dismiss one so it stops coming back. Removed locally on success only —
    /// a failed call must leave it on screen rather than pretend it is gone.
    func dismissNotice(_ id: Int) async {
        guard loggedIn else { return }
        do {
            try await api.markNoticeRead(token: token, id: id)
            notices.removeAll { $0.id == id }
        } catch {
            self.error = (error as? APIError)?.errorDescription
                      ?? error.localizedDescription
        }
    }

    func removeDevice(_ pubkey: String) async {
        guard loggedIn else { return }
        busy = true; defer { busy = false }
        do {
            try await api.deleteDevice(token: token, pubkey: pubkey)
            // Removing THIS device revokes the config the tunnel is using, so
            // the tunnel has to come down with it rather than keep running
            // against a peer that no longer routes it.
            if pubkey == thisDevicePubkey {
                await disconnect()
                SharedStore.clearConfig()
            }
            await refreshAll()
        } catch {
            self.error = (error as? APIError)?.errorDescription ?? error.localizedDescription
        }
    }

    // MARK: Tunnel

    private func loadTunnelManager() async {
        let managers = try? await NETunnelProviderManager.loadAllFromPreferences()
        manager = managers?.first
        tunnelStatus = manager?.connection.status ?? .invalid
    }

    func connect() async {
        guard loggedIn else { error = APIError.notLoggedIn.errorDescription; return }
        busy = true; defer { busy = false }
        error = nil
        do {
            let keypair = try DeviceIdentity.loadOrCreate()
            let reg = try await api.register(
                token: token,
                pubkey: keypair.publicKeyBase64,
                deviceName: Self.deviceName(),
                region: entryRegion,
                exitRegion: isMultihop ? exitRegion : nil)

            let wg = WgConfig(privateKey: keypair.privateKeyBase64,
                              interfaceIP: reg.interfaceIP,
                              interfaceIP6: reg.interfaceIP6?.isEmpty == false
                                            ? reg.interfaceIP6 : nil,
                              dns: reg.dns,
                              peers: reg.peers)
            guard wg.primaryPeer != nil else {
                error = "The control plane returned no node to connect to."
                return
            }
            sameHost = reg.sameHost ?? false
            try SharedStore.writeConfig(wg.serialize())
            try await startTunnel()
            await refreshAll()
        } catch {
            self.error = (error as? APIError)?.errorDescription
                      ?? (error as? LocalizedError)?.errorDescription
                      ?? error.localizedDescription
        }
    }

    private func startTunnel() async throws {
        let mgr = manager ?? NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = "vpn.zerotrust.app.tunnel"
        // Shown in Settings → VPN. There is no single server to name: the
        // mesh picks one per connection.
        proto.serverAddress = isMultihop
            ? "\(entryRegion) → \(exitRegion)" : entryRegion
        mgr.protocolConfiguration = proto
        mgr.localizedDescription = "0trustvpn"
        mgr.isEnabled = true
        try await mgr.saveToPreferences()
        // Reload before starting: saveToPreferences invalidates the in-memory
        // object and startVPNTunnel on a stale one throws.
        try await mgr.loadFromPreferences()
        manager = mgr
        try mgr.connection.startVPNTunnel()
    }

    func disconnect() async {
        manager?.connection.stopVPNTunnel()
        lastHandshake = nil
    }

    /// Ask the extension for the live handshake. NEVPNStatus.connected only
    /// means the extension started — it does not mean the far end ever
    /// answered. The CLI makes the same distinction before telling anyone
    /// their traffic is protected.
    func refreshHandshake() async {
        guard let session = manager?.connection as? NETunnelProviderSession else { return }
        guard let data = "runtime-configuration".data(using: .utf8) else { return }
        let reply: String? = await withCheckedContinuation { cont in
            do {
                try session.sendProviderMessage(data) { resp in
                    cont.resume(returning: resp.flatMap { String(data: $0, encoding: .utf8) })
                }
            } catch {
                cont.resume(returning: nil)
            }
        }
        guard let reply else { return }
        // WireGuard's UAPI reports seconds since epoch.
        for line in reply.split(separator: "\n") {
            guard line.hasPrefix("last_handshake_time_sec=") else { continue }
            let raw = line.dropFirst("last_handshake_time_sec=".count)
            if let secs = TimeInterval(raw), secs > 0 {
                lastHandshake = Date(timeIntervalSince1970: secs)
            }
        }
    }

    /// True only when the tunnel is up AND the far end has actually answered.
    var carryingTraffic: Bool {
        guard tunnelStatus == .connected, let hs = lastHandshake else { return false }
        // WireGuard rekeys well inside three minutes while traffic flows.
        return Date().timeIntervalSince(hs) < 180
    }

    // MARK: Helpers

    private static func mask(_ t: String) -> String {
        guard t.count >= 9 else { return t }
        return "\(t.prefix(4))-****-****-\(t.suffix(4))"
    }

    /// A label for the device list. Deliberately the model, not
    /// UIDevice.current.name — that returns the user's own name on older iOS
    /// ("Jane's iPhone"), and this account is supposed to carry no identity.
    private static func deviceName() -> String {
        #if canImport(UIKit)
        return UIDevice.current.model
        #else
        return "iOS device"
        #endif
    }
}

#if canImport(UIKit)
import UIKit
#endif
