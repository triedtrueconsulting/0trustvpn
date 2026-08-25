0trust.ico is generated, not hand-made.

    python3 make-icon.py

make-icon.py renders the same mark as installer/linux/deb/0trust.svg — dark
rounded square, amber "0" ring, shield, check — at 256, 128, 64, 48, 32 and 16
pixels, and packs them into a multi-resolution .ico. Standard library only; no
ImageMagick, no online converter, no "ask the person building the installer to
produce one", which is what used to be written here and which meant the
documented `wix build` command failed on a clean checkout.

Each size is drawn independently rather than downscaled from one bitmap. The
two smallest drop the shield and check — they cannot survive at that scale —
and thicken the ring so the "0" stays legible in a 16px taskbar slot.

The committed 0trust.ico is the output of that script. Re-run it if the mark
changes, and commit the result.
