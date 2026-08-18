//
// ContentView.swift
// Two screens: login (when no token) and main (when logged in).
//

import SwiftUI

struct ContentView: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        ZStack {
            Color.ztBg.ignoresSafeArea()
            if state.loggedIn {
                MainView()
            } else {
                LoginView()
            }
        }
    }
}

// MARK: - Login

struct LoginView: View {
    @EnvironmentObject var state: AppState
    @State private var tokenInput = ""
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 24) {
            Spacer()
            HStack(alignment: .firstTextBaseline, spacing: 4) {
                Text("0").font(.ztSerifLg).foregroundColor(.ztAmber)
                Text("trust").font(.ztSerifLg).foregroundColor(.ztInk)
            }
            Text("Sign in with your account token.")
                .font(.ztBody).foregroundColor(.ztInkDim)

            TextField("XXXX-XXXX-XXXX-XXXX", text: $tokenInput)
                .font(.ztMono)
                .autocapitalization(.allCharacters)
                .disableAutocorrection(true)
                .padding(14)
                .background(Color.ztBgElev)
                .foregroundColor(.ztInk)
                .cornerRadius(2)
                .overlay(RoundedRectangle(cornerRadius: 2).stroke(Color.ztLine))

            if let error {
                Text(error).font(.ztMono).foregroundColor(.ztTerra)
            }

            Button("Sign in") {
                Task { await signIn() }
            }
            .buttonStyle(PrimaryButtonStyle())

            Spacer()
        }
        .padding(24)
    }

    private func signIn() async {
        do {
            error = nil
            try await state.login(token: tokenInput.uppercased())
        } catch {
            self.error = "Token rejected — check that it matches exactly."
        }
    }
}

// MARK: - Main

struct MainView: View {
    @EnvironmentObject var state: AppState
    @State private var showLogoutConfirm = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                HStack(alignment: .firstTextBaseline, spacing: 4) {
                    Text("0").font(.system(size: 24, weight: .bold, design: .monospaced))
                        .foregroundColor(.ztAmber)
                    Text("trust").font(.system(size: 18, weight: .bold, design: .monospaced))
                        .foregroundColor(.ztInk)
                }
                Spacer()
            }
            .padding(.bottom, 12)

            // Status block
            VStack(spacing: 12) {
                HStack(spacing: 16) {
                    Circle()
                        .fill(state.tunnelStatus == .connected ? Color.ztMoss : Color.ztInkFaint)
                        .frame(width: 14, height: 14)
                    VStack(alignment: .leading) {
                        Text(state.tunnelStatus == .connected ? "Connected" : "Disconnected")
                            .font(.ztSerif).foregroundColor(.ztInk)
                        Text(state.exitRegion.isEmpty ? "single-hop" :
                             "multi-hop · \(state.entryRegion) → \(state.exitRegion)")
                            .font(.ztLabel).foregroundColor(.ztInkFaint)
                            .textCase(.uppercase)
                    }
                    Spacer()
                }
                Button(state.tunnelStatus == .connected ? "Disconnect" : "Connect") {
                    Task {
                        if state.tunnelStatus == .connected {
                            await state.disconnect()
                        } else {
                            try? await state.connect()
                        }
                    }
                }
                .buttonStyle(PrimaryButtonStyle())
            }
            .padding(20)
            .background(Color.ztBgElev)
            .cornerRadius(4)
            .overlay(RoundedRectangle(cornerRadius: 4).stroke(Color.ztLine))

            // Routing card
            VStack(alignment: .leading, spacing: 12) {
                Text("ROUTING").font(.ztLabel).foregroundColor(.ztInkFaint)
                Picker("Entry", selection: $state.entryRegion) {
                    ForEach(["zur", "rey", "buc"], id: \.self) {
                        Text($0.uppercased()).tag($0)
                    }
                }
                .pickerStyle(.menu)
                Picker("Exit", selection: $state.exitRegion) {
                    Text("— single-hop").tag("")
                    ForEach(["zur", "rey", "buc"], id: \.self) {
                        Text($0.uppercased()).tag($0)
                    }
                }
                .pickerStyle(.menu)
            }
            .padding(20)
            .background(Color.ztBgElev)
            .cornerRadius(4)
            .overlay(RoundedRectangle(cornerRadius: 4).stroke(Color.ztLine))

            Spacer()

            Button("Sign out") { showLogoutConfirm = true }
                .foregroundColor(.ztInkDim)
                .font(.ztMono)
        }
        .padding(24)
        .alert("Sign out?", isPresented: $showLogoutConfirm) {
            Button("Sign out", role: .destructive) {
                Task { await state.logout() }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Your token is the only way back. Save it somewhere first.")
        }
        .task { await state.refresh() }
    }
}
