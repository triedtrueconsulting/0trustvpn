Drop a 0trust.ico file in this directory before building the MSI.

Generate from your SVG logo with ImageMagick:
  magick -background none logo.svg \
         -define icon:auto-resize=256,128,64,48,32,16 0trust.ico

Or use any online SVG-to-ICO converter; ensure it produces a multi-resolution
icon containing at least 16, 32, and 256 px variants.
