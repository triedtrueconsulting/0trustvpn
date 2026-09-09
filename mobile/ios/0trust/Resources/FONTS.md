# Bundled faces

The app bundles these five files rather than asking the operator to find them,
because SwiftUI's `Font.custom` does not fail when a name does not resolve —
it substitutes the system font. A missing file therefore ships an app that
builds, launches and connects, and simply looks wrong, with nothing anywhere
reporting a problem.

`../../fetch-fonts.sh` regenerates them from upstream and names each file
after the PostScript name inside it, so the name `Font.custom` looks up and
the name `UIAppFonts` registers cannot drift apart. `--check` verifies that
without a network.

| File | Family | Upstream | Licence |
|------|--------|----------|---------|
| `InstrumentSerif-Regular.ttf` | Instrument Serif | [Instrument/instrument-serif](https://github.com/Instrument/instrument-serif) | SIL Open Font License 1.1 |
| `JetBrainsMono-Regular.ttf` | JetBrains Mono | [JetBrains/JetBrainsMono](https://github.com/JetBrains/JetBrainsMono) | SIL Open Font License 1.1 |
| `JetBrainsMono-Medium.ttf` | JetBrains Mono | same | SIL Open Font License 1.1 |
| `JetBrainsMono-Bold.ttf` | JetBrains Mono | same | SIL Open Font License 1.1 |
| `IBMPlexSans-Regular.ttf` | IBM Plex Sans | [IBM/plex](https://github.com/IBM/plex) | SIL Open Font License 1.1 |

All three families are OFL 1.1, which permits bundling them inside an
application and redistributing them, including commercially. The OFL's one
real condition is the one to keep in mind if the design ever changes: a
modified face may not keep the original's reserved name. We ship them
unmodified.

The same faces are served to the website from `web/fonts/` as woff2, which
iOS cannot load — `UIAppFonts` takes TTF or OTF. That is why there are two
copies and two scripts.
