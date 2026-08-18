//
// Theme.swift
// Matches the warm-dark palette of the web landing site and desktop GUI.
//

import SwiftUI

extension Color {
    static let ztBg        = Color(red: 0.047, green: 0.047, blue: 0.039)  // #0c0c0a
    static let ztBgElev    = Color(red: 0.078, green: 0.078, blue: 0.059)  // #14140f
    static let ztInk       = Color(red: 0.957, green: 0.929, blue: 0.878)  // #f4ede0
    static let ztInkDim    = Color(red: 0.659, green: 0.627, blue: 0.580)  // #a8a094
    static let ztInkFaint  = Color(red: 0.420, green: 0.388, blue: 0.349)  // #6b6359
    static let ztLine      = Color(red: 0.165, green: 0.157, blue: 0.125)  // #2a2820
    static let ztAmber     = Color(red: 0.831, green: 0.647, blue: 0.455)  // #d4a574
    static let ztTerra     = Color(red: 0.769, green: 0.271, blue: 0.212)  // #c44536
    static let ztMoss      = Color(red: 0.490, green: 0.561, blue: 0.353)  // #7d8f5a
}

extension Font {
    static let ztSerif     = Font.custom("InstrumentSerif-Regular", size: 36)
    static let ztSerifLg   = Font.custom("InstrumentSerif-Regular", size: 48)
    static let ztMono      = Font.custom("JetBrainsMono-Regular", size: 13)
    static let ztMonoBold  = Font.custom("JetBrainsMono-Bold", size: 13)
    static let ztBody      = Font.custom("IBMPlexSans-Regular", size: 15)
    static let ztLabel     = Font.custom("JetBrainsMono-Medium", size: 11)
}

// Re-usable button style
struct PrimaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.ztMonoBold)
            .foregroundColor(.ztBg)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 14)
            .background(configuration.isPressed ? Color.ztAmber.opacity(0.85) : Color.ztAmber)
            .cornerRadius(2)
            .textCase(.uppercase)
    }
}
