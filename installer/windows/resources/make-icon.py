#!/usr/bin/env python3
"""
Render 0trust.ico from the same geometry as the SVG logo.

The MSI names `resources\\0trust.ico` and will not build without it. The file
that used to be here was a README telling whoever built the installer to make
one with ImageMagick, which meant the documented build command failed on a
clean checkout and the icon was whatever that person's converter produced.

So the icon is generated, from source, by this script, with no dependencies
beyond the standard library — the same mark as installer/linux/deb/0trust.svg:
a rounded dark square, an amber "0" ring, a shield, and a check inside it.

    python3 make-icon.py            # writes 0trust.ico beside this file

Sizes 16 through 256 are rendered independently rather than downscaled from one
bitmap, because a 16px icon that is a shrunk 256px icon is mud. Each is drawn
with 4x4 supersampling; the small sizes drop the check, which cannot survive at
that scale, and thicken the ring so it does not disappear.
"""
import math
import os
import struct
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "0trust.ico")

BG    = (0x0C, 0x0C, 0x0A)
ELEV  = (0x14, 0x14, 0x0F)
AMBER = (0xD4, 0xA5, 0x74)
MOSS  = (0x7D, 0x8F, 0x5A)

SS = 4          # supersampling factor per axis


# --------------------------------------------------------------------------
# geometry helpers, all in the SVG's 128x128 user space
# --------------------------------------------------------------------------

def rounded_rect(x, y, w, h, r):
    def inside(px, py):
        if not (x <= px <= x + w and y <= py <= y + h):
            return False
        cx = min(max(px, x + r), x + w - r)
        cy = min(max(py, y + r), y + h - r)
        return (px - cx) ** 2 + (py - cy) ** 2 <= r * r
    return inside


def ellipse_ring(cx, cy, rx, ry, width):
    """Approximate distance to the ellipse outline, then band it."""
    half = width / 2.0
    def inside(px, py):
        dx, dy = px - cx, py - cy
        f = (dx / rx) ** 2 + (dy / ry) ** 2 - 1.0
        # |grad f| converts the implicit value into an approximate distance.
        gx, gy = 2 * dx / (rx * rx), 2 * dy / (ry * ry)
        g = math.hypot(gx, gy)
        if g == 0:
            return False
        return abs(f / g) <= half
    return inside


def flatten_cubic(p0, p1, p2, p3, steps=24):
    pts = []
    for i in range(1, steps + 1):
        t = i / steps
        u = 1 - t
        x = (u ** 3 * p0[0] + 3 * u * u * t * p1[0]
             + 3 * u * t * t * p2[0] + t ** 3 * p3[0])
        y = (u ** 3 * p0[1] + 3 * u * u * t * p1[1]
             + 3 * u * t * t * p2[1] + t ** 3 * p3[1])
        pts.append((x, y))
    return pts


def shield_outline():
    """M64 32 L80 40 L80 64 C80 76 72 86 64 90 C56 86 48 76 48 64 L48 40 Z"""
    pts = [(64, 32), (80, 40), (80, 64)]
    pts += flatten_cubic((80, 64), (80, 76), (72, 86), (64, 90))
    pts += flatten_cubic((64, 90), (56, 86), (48, 76), (48, 64))
    pts += [(48, 40)]
    return pts


def polygon(pts):
    def inside(px, py):
        hit = False
        n = len(pts)
        for i in range(n):
            x1, y1 = pts[i]
            x2, y2 = pts[(i + 1) % n]
            if (y1 > py) != (y2 > py):
                xint = x1 + (py - y1) * (x2 - x1) / (y2 - y1)
                if px < xint:
                    hit = not hit
        return hit
    return inside


def _seg_dist(px, py, x1, y1, x2, y2):
    dx, dy = x2 - x1, y2 - y1
    if dx == 0 and dy == 0:
        return math.hypot(px - x1, py - y1)
    t = max(0.0, min(1.0, ((px - x1) * dx + (py - y1) * dy) / (dx * dx + dy * dy)))
    return math.hypot(px - (x1 + t * dx), py - (y1 + t * dy))


def polyline_stroke(pts, width, closed=False):
    half = width / 2.0
    segs = list(zip(pts, pts[1:]))
    if closed:
        segs.append((pts[-1], pts[0]))
    def inside(px, py):
        for (x1, y1), (x2, y2) in segs:
            if _seg_dist(px, py, x1, y1, x2, y2) <= half:
                return True
        return False
    return inside


# --------------------------------------------------------------------------
# rasteriser
# --------------------------------------------------------------------------

def render(size):
    """Return a size*size list of (r, g, b, a) tuples, top row first."""
    scale = 128.0 / size
    detail = size >= 32          # the check and shield only survive this big

    layers = []
    layers.append((rounded_rect(0, 0, 128, 128, 22), BG))
    if detail:
        layers.append((polygon(shield_outline()), ELEV))
        layers.append((polyline_stroke(shield_outline(), 2, closed=True), MOSS))
    # A 6px ring at 128 is under one pixel by 16px; widen as we shrink so the
    # "0" stays a "0" rather than dissolving into a grey smudge.
    ring_w = 6 if size >= 64 else (8 if size >= 32 else 12)
    layers.append((ellipse_ring(64, 64, 36, 42, ring_w), AMBER))
    if detail:
        layers.append((polyline_stroke([(56, 64), (62, 70), (72, 56)], 3), AMBER))

    px = []
    step = scale / SS
    for row in range(size):
        for col in range(size):
            acc_r = acc_g = acc_b = acc_a = 0
            for sy in range(SS):
                for sx in range(SS):
                    ux = (col * scale) + (sx + 0.5) * step
                    uy = (row * scale) + (sy + 0.5) * step
                    hit = None
                    for test, colour in layers:
                        if test(ux, uy):
                            hit = colour
                    if hit is not None:
                        acc_r += hit[0]; acc_g += hit[1]; acc_b += hit[2]
                        acc_a += 255
            n = SS * SS
            if acc_a == 0:
                px.append((0, 0, 0, 0))
            else:
                covered = acc_a / 255.0
                px.append((round(acc_r / covered), round(acc_g / covered),
                           round(acc_b / covered), round(acc_a / n)))
    return px


# --------------------------------------------------------------------------
# encoders
# --------------------------------------------------------------------------

def png_bytes(size, px):
    raw = bytearray()
    for row in range(size):
        raw.append(0)                                  # filter: none
        for col in range(size):
            raw.extend(px[row * size + col])           # RGBA
    def chunk(tag, data):
        c = struct.pack(">I", len(data)) + tag + data
        return c + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
            + chunk(b"IEND", b""))


def dib_bytes(size, px):
    """32-bit BGRA DIB with the doubled height an ICO entry expects."""
    header = struct.pack("<IiiHHIIiiII",
                         40, size, size * 2, 1, 32, 0, size * size * 4,
                         0, 0, 0, 0)
    body = bytearray()
    for row in range(size - 1, -1, -1):                # bottom-up
        for col in range(size):
            r, g, b, a = px[row * size + col]
            body.extend((b, g, r, a))
    # AND mask: unused for 32-bit, but the row-padded block must be present.
    mask_row = ((size + 31) // 32) * 4
    body.extend(b"\x00" * (mask_row * size))
    return header + bytes(body)


def main():
    # 256 goes in as PNG (that is what the format expects at that size);
    # everything smaller as a DIB, which every Windows shell reads.
    sizes = [256, 128, 64, 48, 32, 16]
    images = []
    for s in sizes:
        px = render(s)
        images.append((s, png_bytes(s, px) if s == 256 else dib_bytes(s, px)))
        print(f"  rendered {s}x{s}")

    out = bytearray(struct.pack("<HHH", 0, 1, len(images)))
    offset = 6 + 16 * len(images)
    for s, data in images:
        out.extend(struct.pack("<BBBBHHII",
                               0 if s == 256 else s, 0 if s == 256 else s,
                               0, 0, 1, 32, len(data), offset))
        offset += len(data)
    for _, data in images:
        out.extend(data)

    with open(OUT, "wb") as fh:
        fh.write(bytes(out))
    print(f"wrote {OUT} ({len(out)} bytes, {len(images)} sizes)")


if __name__ == "__main__":
    main()
