//
// ContentView.swift
// The whole interface: sign in, then connect.
//
// Visual language matches the desktop GUI and the site — warm dark, serif
// headings, mono for anything technical. Same palette values, so the three
// surfaces look like one product.
//

import SwiftUI
import NetworkExtension

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
        .preferredColorScheme(.dark)
    }
}

// MARK: - Sign in

struct LoginView: View {
    @EnvironmentObject var state: AppState
    @State private var tokenInput = ""

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Brand()
                    .padding(.top, 48)

                Text("Welcome.")
                    .font(.ztSerifLg)
                    .foregroundColor(.ztInk)
                Text("Sign in with your account token to connect.")
                    .font(.ztBody)
                    .foregroundColor(.ztInkDim)

                Card {
                    Text("ACCOUNT TOKEN")
                        .font(.ztLabel).foregroundColor(.ztInkFaint)
                    TextField("XXXX-XXXX-XXXX-XXXX", text: $tokenInput)
                        .font(.ztMono)
                        .foregroundColor(.ztInk)
                        .textInputAutocapitalization(.characters)
                        .autocorrectionDisabled()
                        .padding(14)
                        .background(Color.ztBg)
                        .cornerRadius(2)
                        .overlay(RoundedRectangle(cornerRadius: 2)
                            .stroke(Color.ztLine))
                    Button("Sign in") {
                        Task { await state.signIn(token: tokenInput) }
                    }
                    .buttonStyle(PrimaryButtonStyle())
                    .disabled(state.busy || tokenInput.isEmpty)
                }

                if let error = state.error {
                    Text(error)
                        .font(.ztMono)
                        .foregroundColor(.ztTerra)
                        .fixedSize(horizontal: false, vertical: true)
                }

                Card {
                    Text("NO ACCOUNT YET?")
                        .font(.ztLabel).foregroundColor(.ztInkFaint)
                    // The offer is rendered, never hardcoded. The trial length
                    // is an operator setting published by /api/v1/config; a
                    // number compiled into an App Store build cannot be
                    // corrected without another trip through review. If the
                    // control plane is unreachable we say less, not something
                    // that might be wrong.
                    Text(trialPitch)
                        .font(.ztBody).foregroundColor(.ztInkDim)
                        .fixedSize(horizontal: false, vertical: true)
                    Link("0trustvpn.com/trial", destination:
                            URL(string: "https://0trustvpn.com/trial")!)
                        .font(.ztMono).foregroundColor(.ztAmber)
                    Text("Or pay with Bitcoin at 0trustvpn.com — your token "
                         + "arrives on the first confirmation.")
                        .font(.ztBody).foregroundColor(.ztInkFaint)
                        .fixedSize(horizontal: false, vertical: true)
                }

                Spacer(minLength: 40)
            }
            .padding(24)
        }
        .task { await state.refreshPublic() }
    }

    private var trialPitch: String {
        let base = "Start a free trial — no email, no card, no name."
        guard let t = state.config?.trial, t.enabled != false, let label = t.label
        else { return base }
        return "Get \(label) free — no email, no card, no name."
    }
}

// MARK: - Main

struct MainView: View {
    @EnvironmentObject var state: AppState
    @State private var showDevices = false
    @State private var confirmSignOut = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Brand()
                StatusCard()
                RoutingCard()
                AccountCard(showDevices: $showDevices,
                            confirmSignOut: $confirmSignOut)
                if let error = state.error {
                    Text(error)
                        .font(.ztMono).foregroundColor(.ztTerra)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 24)
            }
            .padding(20)
        }
        .sheet(isPresented: $showDevices) { DevicesSheet() }
        .alert("Sign out?", isPresented: $confirmSignOut) {
            Button("Sign out", role: .destructive) { Task { await state.signOut() } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Your token is the only way back in. There is no password, "
                 + "no recovery, and no way for us to look it up — save it "
                 + "somewhere before you sign out.")
        }
        .task {
            await state.refreshPublic()
            await state.refreshAll()
        }
    }
}

// MARK: - Cards

private struct StatusCard: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        Card {
            HStack(spacing: 14) {
                Circle()
                    .fill(lightColor)
                    .frame(width: 14, height: 14)
                VStack(alignment: .leading, spacing: 2) {
                    Text(headline)
                        .font(.ztSerif).foregroundColor(.ztInk)
                    Text(subline)
                        .font(.ztLabel).foregroundColor(.ztInkFaint)
                }
                Spacer(minLength: 8)
            }
            Button(state.tunnelStatus == .connected ? "Disconnect" : "Connect") {
                Task {
                    if state.tunnelStatus == .connected {
                        await state.disconnect()
                    } else {
                        await state.connect()
                    }
                }
            }
            .buttonStyle(state.tunnelStatus == .connected
                         ? AnyButtonStyle(DestructiveButtonStyle())
                         : AnyButtonStyle(PrimaryButtonStyle()))
            .disabled(state.busy)

            // Multi-hop on a one-box deployment routes correctly and hides
            // nothing, because entry and exit are the same machine. Say so.
            if state.sameHost && state.isMultihop {
                Text("Entry and exit are the same machine on this deployment. "
                     + "The routing is real; the privacy property multi-hop "
                     + "exists for is not.")
                    .font(.ztBody).foregroundColor(.ztTerra)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var lightColor: Color {
        switch state.tunnelStatus {
        case .connected:  return state.carryingTraffic ? .ztMoss : .ztAmber
        case .connecting, .reasserting, .disconnecting: return .ztAmber
        default: return .ztInkFaint
        }
    }

    private var headline: String {
        switch state.tunnelStatus {
        case .connected:     return "Connected"
        case .connecting:    return "Connecting"
        case .disconnecting: return "Disconnecting"
        case .reasserting:   return "Reconnecting"
        default:             return "Disconnected"
        }
    }

    /// A tunnel that is up has not necessarily carried a packet. Until a
    /// handshake lands we say so rather than implying protection that has not
    /// been demonstrated — the same rule `0trust connect` follows.
    private var subline: String {
        guard state.tunnelStatus == .connected else {
            return state.tunnelStatus == .connecting ? "NEGOTIATING" : "NO TUNNEL"
        }
        if !state.carryingTraffic { return "NO HANDSHAKE YET" }
        return state.isMultihop
            ? "MULTI-HOP · \(state.entryRegion.uppercased()) → \(state.exitRegion.uppercased())"
            : "SINGLE-HOP · \(state.entryRegion.uppercased())"
    }
}

private struct RoutingCard: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        Card {
            Text("ENTRY REGION").font(.ztLabel).foregroundColor(.ztInkFaint)
            Picker("Entry region", selection: $state.entryRegion) {
                ForEach(state.regions) { r in
                    Text(label(r)).tag(r.code)
                }
            }
            .pickerStyle(.menu)
            .tint(.ztInk)

            Text("EXIT REGION").font(.ztLabel).foregroundColor(.ztInkFaint)
            Picker("Exit region", selection: $state.exitRegion) {
                Text("— (single-hop)").tag("")
                // Entry and exit must differ: the control plane rejects a
                // pair that names the same region twice, so never offer it.
                ForEach(state.regions.filter { $0.code != state.entryRegion }) { r in
                    Text(label(r)).tag(r.code)
                }
            }
            .pickerStyle(.menu)
            .tint(.ztInk)

            Text(state.isMultihop
                 ? "Multi-hop: entry decrypts nothing; exit never sees your IP. "
                   + "The pair rotates every 24h."
                 : "Single-hop: one node terminates your tunnel and routes to "
                   + "the internet.")
                .font(.ztBody).foregroundColor(.ztInkDim)
                .fixedSize(horizontal: false, vertical: true)
        }
        // Single-parameter onChange: the two-parameter form is iOS 17 and the
        // deployment target is 16.
        .onChange(of: state.entryRegion) { newValue in
            // Selecting an entry that equals the current exit would make an
            // invalid pair; clear the exit rather than send it.
            if state.exitRegion == newValue { state.exitRegion = "" }
        }
    }

    private func label(_ r: RegionInfo) -> String {
        guard let name = r.name, !name.isEmpty else { return r.code.uppercased() }
        return "\(r.code.uppercased())  \(name)"
    }
}

private struct AccountCard: View {
    @EnvironmentObject var state: AppState
    @Binding var showDevices: Bool
    @Binding var confirmSignOut: Bool

    var body: some View {
        Card {
            KV("account", state.maskedToken, mono: true)
            KV("subscription", subscriptionLine)
            if let exp = state.status?.expiresAt {
                KV("expires", Self.day.string(from:
                    Date(timeIntervalSince1970: TimeInterval(exp))), mono: true)
            }
            // "N / cap", where cap comes from the server. A constant here told
            // trial customers they had slots they did not have.
            KV("devices", "\(state.status?.deviceCount ?? state.devices.count) / \(state.deviceCap)",
               mono: true)

            HStack(spacing: 12) {
                Button("Manage devices") { showDevices = true }
                    .buttonStyle(GhostButtonStyle())
                Button("Sign out") { confirmSignOut = true }
                    .buttonStyle(GhostButtonStyle())
            }
            .padding(.top, 4)
        }
    }

    private var subscriptionLine: String {
        guard let s = state.status else { return "—" }
        guard let plan = s.plan, !plan.isEmpty else { return s.status }
        return "\(s.status) (\(plan))"
    }

    private static let day: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd"
        return f
    }()
}

// MARK: - Devices

private struct DevicesSheet: View {
    @EnvironmentObject var state: AppState
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ZStack {
                Color.ztBg.ignoresSafeArea()
                ScrollView {
                    VStack(alignment: .leading, spacing: 14) {
                        Text("\(state.devices.count) of \(state.deviceCap) slots used"
                             + (state.isTrial ? " (trial)" : ""))
                            .font(.ztBody).foregroundColor(.ztInkDim)

                        if state.devices.isEmpty {
                            Text("No devices registered yet.")
                                .font(.ztBody).foregroundColor(.ztInk)
                        }

                        ForEach(state.devices) { d in
                            DeviceRow(device: d,
                                      isThisDevice: d.pubkey == state.thisDevicePubkey)
                            Divider().background(Color.ztLine)
                        }

                        Text("Removing a device frees its slot and releases its "
                             + "mesh IP. It stops being routed at the next node sync.")
                            .font(.ztBody).foregroundColor(.ztInkFaint)
                            .fixedSize(horizontal: false, vertical: true)
                            .padding(.top, 8)
                    }
                    .padding(20)
                }
            }
            .navigationTitle("Devices")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }.foregroundColor(.ztAmber)
                }
            }
        }
        .task { await state.refreshDevices() }
    }
}

private struct DeviceRow: View {
    @EnvironmentObject var state: AppState
    let device: DeviceInfo
    let isThisDevice: Bool
    @State private var confirming = false

    /// "zur-01 → rey-01" for a multi-hop device, the single node otherwise.
    private var routeLabel: String? {
        guard let entry = device.entryNode, !entry.isEmpty else { return nil }
        if device.multihop == true, let exit = device.exitNode, !exit.isEmpty {
            return "\(entry) → \(exit)"
        }
        return entry
    }

    var body: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 3) {
                Text((device.deviceName?.isEmpty == false
                      ? device.deviceName! : "unnamed")
                     + (isThisDevice ? " · this device" : ""))
                    .font(.ztMonoBold)
                    .foregroundColor(isThisDevice ? .ztAmber : .ztInk)
                if let ip = device.meshIP {
                    Text(ip).font(.ztMono).foregroundColor(.ztInkFaint)
                }
                if let route = routeLabel {
                    Text(route).font(.ztMono).foregroundColor(.ztInkFaint)
                }
            }
            Spacer()
            Button("Remove") { confirming = true }
                .buttonStyle(GhostButtonStyle())
        }
        .alert("Remove this device?", isPresented: $confirming) {
            Button("Remove", role: .destructive) {
                Task { await state.removeDevice(device.pubkey) }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(isThisDevice
                 ? "This is the device you are using. Removing it disconnects "
                   + "the tunnel immediately."
                 : "It stops being routed at the next node sync.")
        }
    }
}

// MARK: - Small pieces

struct Brand: View {
    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 1) {
            Text("0").font(.ztBrandZero).foregroundColor(.ztAmber)
            Text("trust").font(.ztBrand).foregroundColor(.ztInk)
            Spacer()
            Text("v0.1.0").font(.ztLabel).foregroundColor(.ztInkFaint)
        }
    }
}

struct Card<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: 12) { content }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(20)
            .background(Color.ztBgElev)
            .cornerRadius(4)
            .overlay(RoundedRectangle(cornerRadius: 4).stroke(Color.ztLine))
    }
}

struct KV: View {
    let k: String
    let v: String
    var mono = false
    init(_ k: String, _ v: String, mono: Bool = false) {
        self.k = k; self.v = v; self.mono = mono
    }
    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Text(k.uppercased()).font(.ztLabel).foregroundColor(.ztInkFaint)
            Spacer(minLength: 12)
            Text(v)
                .font(mono ? .ztMono : .ztBody)
                .foregroundColor(.ztInk)
                .multilineTextAlignment(.trailing)
        }
    }
}
