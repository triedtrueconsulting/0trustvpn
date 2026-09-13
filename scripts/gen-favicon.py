#!/usr/bin/env python3
"""
Render the GUI's favicon from the same geometry as every other 0trust mark.

The desktop GUI is a browser page, so its window carries a browser tab — and
the tab had no icon. Chrome asked for /favicon.ico on every start, got a 404,
and put a red line in the console; the user got the generic blank-page glyph
on the one window that is supposed to be the product.

Not a second drawing of the logo. installer/windows/resources/make-icon.py
already renders the mark from the same geometry as installer/linux/deb's SVG,
supersampled, with the small sizes simplified so they survive; this imports
render() and png_bytes() from it rather than producing a mark that drifts from
the other three.

    ./scripts/gen-favicon.py           # write the PNG
    ./scripts/gen-favicon.py --check   # verify the committed one is current

--check is what validate.sh runs: the icon is a generated file committed to the
tree, so the thing worth gating is that it still matches its generator.
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
GEN = os.path.join(REPO, "installer", "windows", "resources", "make-icon.py")
OUT = os.path.join(REPO, "client", "internal", "gui", "assets", "favicon.png")

# 32px: the size a browser tab actually renders on a HiDPI display, and large
# enough that the ring and shield are still legible. make-icon.py drops the
# check mark below 32 for that reason.
SIZE = 32


def _load_renderer():
    spec = importlib.util.spec_from_file_location("make_icon", GEN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def build() -> bytes:
    m = _load_renderer()
    return m.png_bytes(SIZE, m.render(SIZE))


def main(argv):
    check = "--check" in argv
    want = build()
    if check:
        if not os.path.exists(OUT):
            print(f"missing: {OUT}\n  run ./scripts/gen-favicon.py", file=sys.stderr)
            return 1
        have = open(OUT, "rb").read()
        if have != want:
            print(f"{OUT} is not what its generator produces.\n"
                  f"  run ./scripts/gen-favicon.py and commit the result",
                  file=sys.stderr)
            return 1
        print(f"favicon.png matches its generator ({len(have)} bytes)")
        return 0
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "wb") as fh:
        fh.write(want)
    print(f"wrote {OUT} ({len(want)} bytes, {SIZE}x{SIZE})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
