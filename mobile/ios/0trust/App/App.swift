//
// App.swift
// 0trustvpn — iOS entry point.
//

import SwiftUI

@main
struct ZeroTrustApp: App {
    @StateObject private var state = AppState()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(state)
                .preferredColorScheme(.dark)
        }
    }
}
