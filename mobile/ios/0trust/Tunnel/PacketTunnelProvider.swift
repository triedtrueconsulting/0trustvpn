//
// PacketTunnelProvider.swift
// The actual VPN extension that handles packets when the user taps Connect.
//
// In production, replace the placeholder code with WireGuardKit's
// WireGuardAdapter. The flow is:
//
//   1. Load the wg-quick-style config from App Group UserDefaults
//   2. Parse it with TunnelConfiguration.init(fromWgQuickConfig:)
//   3. Call adapter.start(tunnelConfiguration:) inside startTunnel(...)
//   4. Forward setNetworkSettings(...) so iOS configures routing
//
// See: https://git.zx2c4.com/wireguard-apple/tree/Sources/WireGuardKit
//

import NetworkExtension
import os.log

class PacketTunnelProvider: NEPacketTunnelProvider {
    private let log = OSLog(subsystem: "vpn.zerotrust.app", category: "tunnel")

    override func startTunnel(options: [String: NSObject]?,
                              completionHandler: @escaping (Error?) -> Void) {
        os_log("startTunnel", log: log, type: .info)

        guard let defaults = UserDefaults(suiteName: "group.vpn.zerotrust.app"),
              let config = defaults.string(forKey: "wg.config") else {
            completionHandler(NSError(domain: "0trust", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "no wg.config in App Group"]))
            return
        }

        // TODO: replace with real WireGuardKit integration
        //
        //   let tunConfig = try TunnelConfiguration(fromWgQuickConfig: config)
        //   let adapter = WireGuardAdapter(with: self) { _, message in
        //     os_log("%{public}@", log: self.log, type: .info, message)
        //   }
        //   adapter.start(tunnelConfiguration: tunConfig) { error in
        //     completionHandler(error)
        //   }
        _ = config
        completionHandler(nil)
    }

    override func stopTunnel(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        os_log("stopTunnel: %d", log: log, type: .info, reason.rawValue)
        // TODO: adapter.stop { _ in completionHandler() }
        completionHandler()
    }
}
