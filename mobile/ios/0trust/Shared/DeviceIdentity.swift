//
// DeviceIdentity.swift
// This device's WireGuard keypair — generated ONCE and kept.
//
// Registration is idempotent on the public key: re-presenting the same key
// returns the existing device and keeps its mesh IP. Generating a fresh key
// on every connect instead registers a NEW device each time, which burns the
// account's device cap (2 on a trial, 8 paid) in a handful of reconnects and
// then locks the customer out of their own subscription with a 409. The
// Android app shipped exactly that bug and had to be fixed; this is the same
// invariant on iOS, written down so it is not rediscovered a third time.
//
// The private key never leaves the device and is never sent to the control
// plane — only the public key is registered.
//

import Foundation
import WireGuardKit

struct DeviceKeypair {
    let privateKey: PrivateKey
    var publicKeyBase64: String { privateKey.publicKey.base64Key }
    var privateKeyBase64: String { privateKey.base64Key }
}

enum DeviceIdentity {
    /// The device's keypair, restored from the keychain or created on first
    /// use. Both the app and the tunnel extension resolve the same one.
    static func loadOrCreate() throws -> DeviceKeypair {
        if let stored = Keychain.get(Keychain.privateKeyKey),
           let key = PrivateKey(base64Key: stored) {
            return DeviceKeypair(privateKey: key)
        }
        let key = PrivateKey()
        try Keychain.set(key.base64Key, for: Keychain.privateKeyKey)
        try Keychain.set(key.publicKey.base64Key, for: Keychain.publicKeyKey)
        return DeviceKeypair(privateKey: key)
    }

    /// The public key without touching the private one — for showing which
    /// row in the device list is this phone.
    static var publicKeyBase64: String? {
        Keychain.get(Keychain.publicKeyKey)
    }

    /// Only on sign-out. The device stays registered on the account until it
    /// is removed explicitly, so a customer who signs back in on the same
    /// phone does not silently consume a second slot.
    static func forget() {
        Keychain.delete(Keychain.privateKeyKey)
        Keychain.delete(Keychain.publicKeyKey)
    }
}
