//
// Keychain.swift
// The only place secrets are written on this device.
//
// Two things live here: the account token, which IS the credential (there is
// no password to fall back on, and no way for us to look one up), and the
// device's WireGuard private key. Both are shared with the tunnel extension
// through a keychain access group, because the extension runs in its own
// process and has to bring the tunnel up without the app being open.
//
// kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, deliberately:
//   - AfterFirstUnlock, not WhenUnlocked, because the packet-tunnel extension
//     is started by iOS on demand — on-demand connect, or Always-on VPN after
//     a reboot — and the screen may well be locked when it happens.
//   - ThisDeviceOnly so the token never rides an iCloud keychain backup to
//     another device. An anonymous token that syncs is an anonymous token
//     sitting in somebody's iCloud account.
//

import Foundation
import Security

enum KeychainError: Error, LocalizedError {
    case status(OSStatus)
    case malformed

    var errorDescription: String? {
        switch self {
        case .status(let s): return "keychain error \(s)"
        case .malformed:     return "keychain item was not valid UTF-8"
        }
    }
}

enum Keychain {
    /// Shared with the tunnel extension. Must match the keychain-access-groups
    /// entitlement on BOTH targets, and is prefixed with the team id at
    /// runtime by iOS.
    static let accessGroup = "group.vpn.zerotrust.app"

    static let tokenKey       = "account-token"
    static let privateKeyKey  = "device-private-key"
    static let publicKeyKey   = "device-public-key"

    private static func query(_ account: String) -> [String: Any] {
        [
            kSecClass as String:            kSecClassGenericPassword,
            kSecAttrService as String:      "vpn.zerotrust.app",
            kSecAttrAccount as String:      account,
            kSecAttrAccessGroup as String:  accessGroup,
        ]
    }

    static func set(_ value: String, for account: String) throws {
        guard let data = value.data(using: .utf8) else { throw KeychainError.malformed }
        var q = query(account)
        SecItemDelete(q as CFDictionary)
        q[kSecValueData as String] = data
        q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(q as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainError.status(status) }
    }

    static func get(_ account: String) -> String? {
        var q = query(account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess,
              let data = out as? Data,
              let s = String(data: data, encoding: .utf8) else { return nil }
        return s
    }

    static func delete(_ account: String) {
        SecItemDelete(query(account) as CFDictionary)
    }
}
