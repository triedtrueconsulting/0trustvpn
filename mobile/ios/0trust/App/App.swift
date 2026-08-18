//
// App.swift
// 0trust iOS app
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
