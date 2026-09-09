#!/usr/bin/env python3
"""
Render web/og.png — the 1200x630 card shown when a 0trustvpn link is pasted
into a chat, a social post, or an AI assistant's citation.

Generated rather than committed as an opaque binary, and with no
dependencies, for the same reason make-icon.py is: the alternative is a file
nobody can regenerate, whose provenance is "someone had Photoshop once", and
which quietly keeps showing last year's tagline.

There is no image library here, so this does two things by hand:

  * writes the PNG (zlib + struct, same as make-icon.py); and
  * rasterises text out of the TrueType files the iOS app already bundles,
    which is what makes this a card rather than a logo on a rectangle.
    Only what these faces need is implemented: cmap format 4, simple and
    composite glyphs, quadratic contours, scanline fill with the non-zero
    winding rule. It is not a general renderer and should not become one.

    ./scripts/make-og-image.py        # writes web/og.png
"""
import os, struct, sys, zlib

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FONTS = os.path.join(REPO, "mobile", "ios", "0trust", "Resources")
OUT = os.path.join(REPO, "web", "og.png")

W, H = 1200, 630
BG    = (0x0c, 0x0c, 0x0a)
INK   = (0xf4, 0xed, 0xe0)
DIM   = (0xa8, 0xa0, 0x94)
AMBER = (0xd4, 0xa5, 0x74)
MOSS  = (0x7d, 0x8f, 0x5a)
LINE  = (0x2a, 0x28, 0x20)


# ---------------------------------------------------------------- fonts ----
class Font:
    def __init__(self, path):
        self.d = open(path, "rb").read()
        n = struct.unpack(">H", self.d[4:6])[0]
        self.t = {}
        for i in range(n):
            o = 12 + 16 * i
            tag = self.d[o:o+4].decode("latin1")
            self.t[tag] = struct.unpack(">II", self.d[o+8:o+16])
        head = self.t["head"][0]
        self.upem = struct.unpack(">H", self.d[head+18:head+20])[0]
        self.long_loca = struct.unpack(">h", self.d[head+50:head+52])[0] == 1
        hhea = self.t["hhea"][0]
        self.num_hmetrics = struct.unpack(">H", self.d[hhea+34:hhea+36])[0]
        self.cmap = self._cmap()

    def _cmap(self):
        base = self.t["cmap"][0]
        n = struct.unpack(">H", self.d[base+2:base+4])[0]
        sub = None
        for i in range(n):
            pid, eid, off = struct.unpack(">HHI", self.d[base+4+8*i:base+12+8*i])
            if (pid, eid) in ((3, 1), (3, 10), (0, 3), (0, 4)):
                sub = base + off
        if sub is None:
            raise SystemExit("no unicode cmap")
        fmt = struct.unpack(">H", self.d[sub:sub+2])[0]
        if fmt != 4:
            raise SystemExit(f"cmap format {fmt} not implemented")
        segx2 = struct.unpack(">H", self.d[sub+6:sub+8])[0]
        seg = segx2 // 2
        def arr(o):
            return struct.unpack(f">{seg}H", self.d[o:o+segx2])
        ends   = arr(sub + 14)
        starts = arr(sub + 16 + segx2)
        deltas = struct.unpack(f">{seg}h", self.d[sub+16+2*segx2:sub+16+3*segx2])
        ro_off = sub + 16 + 3 * segx2
        ranges = arr(ro_off)
        m = {}
        for i in range(seg):
            for c in range(starts[i], min(ends[i], 0x2200) + 1):
                if c == 0xFFFF:
                    continue
                if ranges[i] == 0:
                    g = (c + deltas[i]) & 0xFFFF
                else:
                    gi = ro_off + 2*i + ranges[i] + 2*(c - starts[i])
                    g = struct.unpack(">H", self.d[gi:gi+2])[0]
                    if g:
                        g = (g + deltas[i]) & 0xFFFF
                if g:
                    m[c] = g
        return m

    def advance(self, gid):
        hmtx = self.t["hmtx"][0]
        i = min(gid, self.num_hmetrics - 1)
        return struct.unpack(">H", self.d[hmtx+4*i:hmtx+4*i+2])[0]

    def _loca(self, gid):
        o = self.t["loca"][0]
        if self.long_loca:
            a, b = struct.unpack(">II", self.d[o+4*gid:o+4*gid+8])
        else:
            a, b = struct.unpack(">HH", self.d[o+2*gid:o+2*gid+4])
            a, b = a * 2, b * 2
        return a, b

    def contours(self, gid, depth=0):
        """[[(x, y, on_curve), ...], ...] in font units."""
        a, b = self._loca(gid)
        if a == b or depth > 4:
            return []
        g = self.t["glyf"][0] + a
        nc = struct.unpack(">h", self.d[g:g+2])[0]
        if nc < 0:
            return self._composite(g + 10, depth)
        ends = struct.unpack(f">{nc}H", self.d[g+10:g+10+2*nc])
        npt = ends[-1] + 1
        p = g + 10 + 2*nc
        p += 2 + struct.unpack(">H", self.d[p:p+2])[0]        # skip hinting
        flags = []
        while len(flags) < npt:
            f = self.d[p]; p += 1
            flags.append(f)
            if f & 8:
                r = self.d[p]; p += 1
                flags.extend([f] * r)
        def coords(short_bit, same_bit):
            vals, v = [], 0
            nonlocal p
            for f in flags:
                if f & short_bit:
                    d = self.d[p]; p += 1
                    v += d if f & same_bit else -d
                elif not f & same_bit:
                    v += struct.unpack(">h", self.d[p:p+2])[0]; p += 2
                vals.append(v)
            return vals
        xs = coords(2, 16)
        ys = coords(4, 32)
        out, start = [], 0
        for e in ends:
            out.append([(xs[i], ys[i], bool(flags[i] & 1))
                        for i in range(start, e + 1)])
            start = e + 1
        return out

    def _composite(self, p, depth):
        out = []
        while True:
            flags, gi = struct.unpack(">HH", self.d[p:p+4]); p += 4
            if flags & 1:
                a1, a2 = struct.unpack(">hh", self.d[p:p+4]); p += 4
            else:
                a1, a2 = struct.unpack(">bb", self.d[p:p+2]); p += 2
            if flags & 8:      p += 2
            elif flags & 0x40: p += 4
            elif flags & 0x80: p += 8
            dx, dy = (a1, a2) if flags & 2 else (0, 0)
            for c in self.contours(gi, depth + 1):
                out.append([(x + dx, y + dy, on) for x, y, on in c])
            if not flags & 0x20:
                break
        return out


def glyph_polys(font, gid, size, x0, y0):
    """Contours as flattened device-space polygons. y grows downward."""
    s = size / font.upem
    polys = []
    for c in font.contours(gid):
        if not c:
            continue
        # Insert the implied on-curve midpoints so every off-curve point is a
        # single quadratic control point.
        pts = []
        for i, (x, y, on) in enumerate(c):
            nx, ny, non = c[(i + 1) % len(c)]
            pts.append((x, y, on))
            if not on and not non:
                pts.append(((x + nx) / 2, (y + ny) / 2, True))
        if not any(p[2] for p in pts):
            continue
        while not pts[0][2]:
            pts.append(pts.pop(0))
        out, i = [], 0
        cur = pts[0]
        out.append(cur)
        i = 1
        while i <= len(pts):
            p = pts[i % len(pts)]
            if p[2]:
                out.append(p); cur = p; i += 1
            else:
                nxt = pts[(i + 1) % len(pts)]
                for k in range(1, 9):
                    t = k / 8.0
                    u = 1 - t
                    out.append((u*u*cur[0] + 2*u*t*p[0] + t*t*nxt[0],
                                u*u*cur[1] + 2*u*t*p[1] + t*t*nxt[1], True))
                cur = nxt; i += 2
        polys.append([(x0 + x * s, y0 - y * s) for x, y, _ in out])
    return polys


# -------------------------------------------------------------- raster -----
class Canvas:
    def __init__(self, w, h, bg):
        self.w, self.h = w, h
        self.px = bytearray(bytes(bg) * (w * h))

    def blend(self, x, y, colour, a):
        if a <= 0 or not (0 <= x < self.w and 0 <= y < self.h):
            return
        i = (y * self.w + x) * 3
        if a >= 1:
            self.px[i:i+3] = bytes(colour); return
        for k in range(3):
            self.px[i+k] = round(self.px[i+k] * (1 - a) + colour[k] * a)

    def rect(self, x, y, w, h, colour, a=1.0):
        for yy in range(max(0, y), min(self.h, y + h)):
            for xx in range(max(0, x), min(self.w, x + w)):
                self.blend(xx, yy, colour, a)

    def fill_polys(self, polys, colour, ss=4):
        """Non-zero winding scanline fill, ss subsamples per axis."""
        if not polys:
            return
        edges = []
        for poly in polys:
            for i in range(len(poly)):
                x1, y1 = poly[i]
                x2, y2 = poly[(i + 1) % len(poly)]
                if y1 != y2:
                    edges.append((x1, y1, x2, y2))
        if not edges:
            return
        ys = [e[1] for e in edges] + [e[3] for e in edges]
        xs = [e[0] for e in edges] + [e[2] for e in edges]
        y_lo, y_hi = max(0, int(min(ys)) - 1), min(self.h, int(max(ys)) + 2)
        x_lo, x_hi = max(0, int(min(xs)) - 1), min(self.w, int(max(xs)) + 2)
        cov = {}
        for row in range(y_lo, y_hi):
            for sy in range(ss):
                yc = row + (sy + 0.5) / ss
                hits = []
                for x1, y1, x2, y2 in edges:
                    if (y1 <= yc < y2) or (y2 <= yc < y1):
                        t = (yc - y1) / (y2 - y1)
                        hits.append((x1 + t * (x2 - x1), 1 if y2 > y1 else -1))
                if not hits:
                    continue
                hits.sort()
                wind = 0
                for i in range(len(hits) - 1):
                    wind += hits[i][1]
                    if wind == 0:
                        continue
                    xa, xb = hits[i][0], hits[i + 1][0]
                    for col in range(max(x_lo, int(xa)), min(x_hi, int(xb) + 1)):
                        for sx in range(ss):
                            xc = col + (sx + 0.5) / ss
                            if xa <= xc < xb:
                                cov[(col, row)] = cov.get((col, row), 0) + 1
        n = ss * ss
        for (x, y), c in cov.items():
            self.blend(x, y, colour, min(1.0, c / n))

    def text(self, font, s, size, x, y, colour, tracking=0.0):
        pen = x
        for ch in s:
            gid = font.cmap.get(ord(ch))
            if gid is None:
                pen += size * 0.4; continue
            self.fill_polys(glyph_polys(font, gid, size, pen, y), colour)
            pen += font.advance(gid) * size / font.upem + tracking
        return pen

    def width(self, font, s, size, tracking=0.0):
        w = 0
        for ch in s:
            gid = font.cmap.get(ord(ch))
            w += (font.advance(gid) * size / font.upem if gid else size * 0.4)
            w += tracking
        return w

    def png(self):
        raw = bytearray()
        for r in range(self.h):
            raw.append(0)
            raw.extend(self.px[r * self.w * 3:(r + 1) * self.w * 3])
        def chunk(tag, data):
            return (struct.pack(">I", len(data)) + tag + data
                    + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))
        return (b"\x89PNG\r\n\x1a\n"
                + chunk(b"IHDR", struct.pack(">IIBBBBB", self.w, self.h, 8, 2, 0, 0, 0))
                + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
                + chunk(b"IEND", b""))


def ring(c, cx, cy, rx, ry, width, colour, ss=4):
    inner_x, inner_y = rx - width, ry - width
    for y in range(int(cy - ry) - 1, int(cy + ry) + 2):
        for x in range(int(cx - rx) - 1, int(cx + rx) + 2):
            hit = 0
            for sy in range(ss):
                for sx in range(ss):
                    px = x + (sx + .5) / ss - cx
                    py = y + (sy + .5) / ss - cy
                    if (px/rx)**2 + (py/ry)**2 <= 1 and \
                       (px/inner_x)**2 + (py/inner_y)**2 >= 1:
                        hit += 1
            if hit:
                c.blend(x, y, colour, hit / (ss * ss))


def stroke(c, pts, width, colour, ss=3):
    half = width / 2
    xs = [p[0] for p in pts]; ys = [p[1] for p in pts]
    for y in range(int(min(ys) - width), int(max(ys) + width) + 1):
        for x in range(int(min(xs) - width), int(max(xs) + width) + 1):
            hit = 0
            for sy in range(ss):
                for sx in range(ss):
                    px, py = x + (sx + .5)/ss, y + (sy + .5)/ss
                    for i in range(len(pts) - 1):
                        x1, y1 = pts[i]; x2, y2 = pts[i + 1]
                        dx, dy = x2 - x1, y2 - y1
                        L = dx*dx + dy*dy
                        t = 0 if L == 0 else max(0, min(1, ((px-x1)*dx + (py-y1)*dy) / L))
                        ddx, ddy = px - (x1 + t*dx), py - (y1 + t*dy)
                        if ddx*ddx + ddy*ddy <= half*half:
                            hit += 1; break
            if hit:
                c.blend(x, y, colour, min(1.0, hit / (ss*ss)))


def main():
    serif = Font(os.path.join(FONTS, "InstrumentSerif-Regular.ttf"))
    mono  = Font(os.path.join(FONTS, "JetBrainsMono-Bold.ttf"))
    monor = Font(os.path.join(FONTS, "JetBrainsMono-Regular.ttf"))
    sans  = Font(os.path.join(FONTS, "IBMPlexSans-Regular.ttf"))

    c = Canvas(W, H, BG)

    # The site's own background grid, at the site's own opacity.
    for x in range(0, W, 64):
        c.rect(x, 0, 1, H, INK, 0.025)
    for y in range(0, H, 64):
        c.rect(0, y, W, 1, INK, 0.025)

    # Mark: the favicon's ring and check, scaled up.
    ring(c, 118, 150, 46, 54, 11, AMBER)
    stroke(c, [(102, 150), (114, 163), (135, 133)], 9, AMBER)

    # Wordmark, in the face the site sets it in.
    pen = c.text(mono, "0", 46, 190, 168, AMBER)
    c.text(mono, "trustvpn", 46, pen, 168, INK)

    # Headline.
    c.text(serif, "Encrypted mesh.", 88, 72, 300, INK)
    c.text(serif, "No accounts. No logs.", 88, 72, 396, INK)

    # Supporting line.
    c.text(sans, "Multi-hop WireGuard through Switzerland, Iceland and Romania.",
           27, 74, 452, DIM)
    c.text(sans, "No email, no password — an anonymous token and crypto.",
           27, 74, 490, DIM)

    # Footer rule and the two facts most worth carrying into a preview.
    c.rect(72, 536, W - 144, 1, LINE)
    c.text(monor, "ZUR · REY · BUC", 22, 74, 588, AMBER, tracking=1.2)
    label = "0trustvpn.com"
    c.text(monor, label, 22, W - 74 - c.width(monor, label, 22, 1.2), 588,
           MOSS, tracking=1.2)

    open(OUT, "wb").write(c.png())
    print(f"wrote web/og.png — {W}x{H}, {os.path.getsize(OUT)} bytes")


if __name__ == "__main__":
    sys.exit(main())
