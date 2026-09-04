//
// PacketTunnelProvider.swift
// The network extension that actually carries packets.
//
// This runs in its own process, started by iOS on demand — from the app, from
// on-demand rules, or after a reboot under Always-on VPN with the app never
// launched. It therefore reads everything it needs from the shared App Group
// container and the shared keychain, and assumes the app is not running.
//
// The previous version of this file called completionHandler(nil) without
// starting anything. iOS would have shown "Connected" in Settings while no
// packet was ever encrypted — a tunnel that reports success and carries
// nothing is the one outcome a VPN must never produce. It now fails loudly
// instead: if the adapter cannot start, the error propagates and the
// connection goes down.
//

import NetworkExtension
import WireGuardKit
import os.log

class PacketTunnelProvider: NEPacketTunnelProvider {
    private lazy var adapter: WireGuardAdapter = {
        WireGuardAdapter(with: self) { logLevel, message in
            os_log("%{public}@", log: Self.log,
                   type: logLevel == .error ? .error : .info, message)
        }
    }()

    private static let log = OSLog(subsystem: "vpn.zerotrust.app", category: "tunnel")

    override func startTunnel(options: [String: NSObject]?,
                              completionHandler: @escaping (Error?) -> Void) {
        os_log("startTunnel", log: Self.log, type: .info)

        let text: String
        do {
            text = try SharedStore.readConfig()
        } catch {
            os_log("no tunnel configuration: %{public}@", log: Self.log, type: .error,
                   error.localizedDescription)
            completionHandler(TunnelError.noConfiguration)
            return
        }

        let tunnelConfiguration: TunnelConfiguration
        do {
            tunnelConfiguration = try TunnelConfiguration(fromWgQuickConfig: text,
                                                          called: "0trust")
        } catch {
            os_log("unparseable configuration: %{public}@", log: Self.log, type: .error,
                   String(describing: error))
            completionHandler(TunnelError.badConfiguration)
            return
        }

        adapter.start(tunnelConfiguration: tunnelConfiguration) { adapterError in
            if let adapterError {
                os_log("adapter failed to start: %{public}@", log: Self.log, type: .error,
                       String(describing: adapterError))
                completionHandler(TunnelError.adapter(String(describing: adapterError)))
                return
            }
            os_log("tunnel up", log: Self.log, type: .info)
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        os_log("stopTunnel: %d", log: Self.log, type: .info, reason.rawValue)
        adapter.stop { error in
            if let error {
                os_log("adapter stop error: %{public}@", log: Self.log, type: .error,
                       String(describing: error))
            }
            completionHandler()
        }
    }

    /// The app asks for the live handshake over this channel rather than
    /// trusting NEVPNStatus. `wg-quick up` equivalents return success once the
    /// interface exists, which says nothing about whether the far end ever
    /// answered — the desktop client makes the same distinction before it
    /// tells anyone they are protected.
    override func handleAppMessage(_ messageData: Data,
                                   completionHandler: ((Data?) -> Void)?) {
        guard let message = String(data: messageData, encoding: .utf8),
              message == "runtime-configuration" else {
            completionHandler?(nil)
            return
        }
        adapter.getRuntimeConfiguration { settings in
            completionHandler?(settings?.data(using: .utf8))
        }
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        completionHandler()
    }

    override func wake() {}
}

enum TunnelError: Error, LocalizedError {
    case noConfiguration
    case badConfiguration
    case adapter(String)

    var errorDescription: String? {
        switch self {
        case .noConfiguration:
            return "No tunnel configuration — open 0trustvpn and connect once."
        case .badConfiguration:
            return "The stored tunnel configuration could not be parsed."
        case .adapter(let detail):
            return "WireGuard could not start: \(detail)"
        }
    }
}
