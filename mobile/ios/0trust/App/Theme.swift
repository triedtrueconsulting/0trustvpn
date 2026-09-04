//
// Theme.swift
// The same warm-dark palette as the website and the desktop GUI, so the three
// surfaces read as one product. Values are copied from the design system in
// CLAUDE.md; changing one here means changing it in all three.
//

import SwiftUI

extension Color {
    static let ztBg       = Color(red: 0.047, green: 0.047, blue: 0.039)  // #0c0c0a
    static let ztBgElev   = Color(red: 0.078, green: 0.078, blue: 0.059)  // #14140f
    static let ztInk      = Color(red: 0.957, green: 0.929, blue: 0.878)  // #f4ede0
    static let ztInkDim   = Color(red: 0.659, green: 0.627, blue: 0.580)  // #a8a094
    static let ztInkFaint = Color(red: 0.420, green: 0.388, blue: 0.349)  // #6b6359
    static let ztLine     = Color(red: 0.165, green: 0.157, blue: 0.125)  // #2a2820
    static let ztAmber    = Color(red: 0.831, green: 0.647, blue: 0.455)  // #d4a574
    static let ztTerra    = Color(red: 0.769, green: 0.271, blue: 0.212)  // #c44536
    static let ztMoss     = Color(red: 0.490, green: 0.561, blue: 0.353)  // #7d8f5a
}

// The three families are bundled with the app (see project.yml → fonts). Each
// falls back to a system face of the same character if a face fails to load,
// so a missing resource degrades instead of rendering nothing.
extension Font {
    static let ztSerifLg   = custom("InstrumentSerif-Regular", size: 40,
                                    relativeTo: .largeTitle)
    static let ztSerif     = custom("InstrumentSerif-Regular", size: 27,
                                    relativeTo: .title)
    static let ztBrandZero = custom("JetBrainsMono-Bold", size: 26,
                                    relativeTo: .title2)
    static let ztBrand     = custom("JetBrainsMono-Bold", size: 20,
                                    relativeTo: .title3)
    static let ztMono      = custom("JetBrainsMono-Regular", size: 13,
                                    relativeTo: .callout)
    static let ztMonoBold  = custom("JetBrainsMono-Bold", size: 13,
                                    relativeTo: .callout)
    static let ztBody      = custom("IBMPlexSans-Regular", size: 15,
                                    relativeTo: .body)
    static let ztLabel     = custom("JetBrainsMono-Medium", size: 11,
                                    relativeTo: .caption)
}

// MARK: - Button styles

/// The single affirmative action on a screen.
struct PrimaryButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.ztMonoBold)
            .textCase(.uppercase)
            .kerning(1.2)
            .foregroundColor(.ztBg)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 15)
            .background(Color.ztAmber
                .opacity(configuration.isPressed ? 0.82 : 1))
            .opacity(isEnabled ? 1 : 0.4)
            .cornerRadius(3)
    }
}

/// Disconnect is not the primary action and must not look like it — outlined,
/// and only reddening on press. Same decision the desktop GUI makes.
struct DestructiveButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.ztMonoBold)
            .textCase(.uppercase)
            .kerning(1.2)
            .foregroundColor(configuration.isPressed ? .ztTerra : .ztInkDim)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 15)
            .background(Color.ztTerra.opacity(configuration.isPressed ? 0.08 : 0))
            .overlay(RoundedRectangle(cornerRadius: 3)
                .stroke(configuration.isPressed ? Color.ztTerra : Color.ztLine))
            .opacity(isEnabled ? 1 : 0.4)
            .cornerRadius(3)
    }
}

/// Secondary actions: quiet until touched.
struct GhostButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.ztLabel)
            .textCase(.uppercase)
            .kerning(0.8)
            .foregroundColor(configuration.isPressed ? .ztAmber : .ztInkDim)
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
            .overlay(RoundedRectangle(cornerRadius: 2)
                .stroke(configuration.isPressed ? Color.ztAmber : Color.ztLine))
            .opacity(isEnabled ? 1 : 0.4)
    }
}

/// Lets one view pick between two styles at runtime — the connect button
/// swaps between primary and destructive, and ButtonStyle is not existential.
struct AnyButtonStyle: ButtonStyle {
    private let make: (Configuration) -> AnyView

    init<S: ButtonStyle>(_ style: S) {
        make = { AnyView(style.makeBody(configuration: $0)) }
    }

    func makeBody(configuration: Configuration) -> some View {
        make(configuration)
    }
}
