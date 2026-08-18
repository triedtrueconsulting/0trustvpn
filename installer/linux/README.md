# 0trust VPN — Linux installers

Two distribution formats, both producing the same binary plus a desktop launcher entry:

| Format | Best for | Output |
|--------|----------|--------|
| **`.deb`** | Debian, Ubuntu, Mint, Pop!_OS, elementary — anything Debian-derived | `0trust_0.1.0_amd64.deb`, `0trust_0.1.0_arm64.deb` |
| **AppImage** | Anything else: Fedora, Arch, openSUSE, NixOS, etc. | `0trust-0.1.0-x86_64.AppImage` |

For RPM-based distros that want a native package, `alien` converts the .deb cleanly; or a future iteration can add an `.rpm` builder.

```
installer/linux/
├── deb/
│   ├── build.sh          Build amd64 + arm64 .debs
│   ├── 0trust.desktop    Desktop launcher entry
│   ├── 0trust.svg        Application icon
│   └── copyright         Debian copyright file
├── appimage/
│   └── build.sh          Build AppImage; auto-fetches appimagetool
└── README.md             (this file)
```

## Build

Both scripts read pre-built Go binaries from `client/dist/`. Build those first:

```bash
cd client
make linux           # produces dist/0trust-linux-amd64 + dist/0trust-linux-arm64
cd ..
```

Then:

```bash
# .deb (amd64 + arm64 in one run)
sudo apt-get install -y dpkg-dev       # one-time
./installer/linux/deb/build.sh

# AppImage (x86_64)
./installer/linux/appimage/build.sh

# AppImage (arm64) — run on an aarch64 host or with qemu-user-static
ARCH=aarch64 ./installer/linux/appimage/build.sh
```

Outputs land in `installer/linux/{deb,appimage}/out/`.

## What the .deb does

- Installs `/usr/bin/0trust`
- Installs the desktop entry at `/usr/share/applications/0trust.desktop` so 0trust appears in the application menu under Network/Security
- Installs the SVG icon at `/usr/share/icons/hicolor/scalable/apps/0trust.svg`
- Depends on `wireguard-tools` (so `wg`, `wg-quick` are available)
- Recommends `wireguard` (the kernel-module package; not strictly required on 5.6+ kernels which have WireGuard in mainline)
- Refreshes the icon + desktop cache in `postinst` so the launcher appears immediately without a logout

After install, customers can:
- Run `0trust` from any shell (it's in `/usr/bin`)
- Launch the GUI from the application menu (which runs `0trust gui` for them)
- Uninstall cleanly with `sudo apt-get remove 0trust`

## What the AppImage does

- Single executable file ~6 MB
- Bundles only the 0trust binary plus the desktop entry + icon (no libraries; the Go binary is statically linked)
- Runs on any glibc-2.17+ Linux (CentOS 7-era and newer)
- Doesn't require root; doesn't need a package manager
- Customers download, `chmod +x`, run

The tradeoff: AppImages don't integrate with the system package manager, so updates require manually downloading the next version. Acceptable for a small user base, suboptimal for thousands.

## Signing

Both formats benefit from PGP detached signatures alongside the artifacts:

```bash
# In your release directory
gpg --detach-sign --armor 0trust_0.1.0_amd64.deb
gpg --detach-sign --armor 0trust-0.1.0-x86_64.AppImage
```

The same `verify-release.sh` script that verifies the Windows MSI also verifies these.

## APT repository (optional, for auto-updates)

Hosting an APT repo at `https://apt.0trustvpn.com/` lets Debian/Ubuntu users `apt-get install 0trust` and receive automatic updates. The minimum viable setup:

```bash
# On the apt host
mkdir -p /var/www/apt/dists/stable/main/binary-{amd64,arm64}
cp 0trust_0.1.0_amd64.deb /var/www/apt/dists/stable/main/binary-amd64/
cp 0trust_0.1.0_arm64.deb /var/www/apt/dists/stable/main/binary-arm64/

cd /var/www/apt
apt-ftparchive packages dists/stable/main/binary-amd64 \
  > dists/stable/main/binary-amd64/Packages
gzip -k dists/stable/main/binary-amd64/Packages
apt-ftparchive packages dists/stable/main/binary-arm64 \
  > dists/stable/main/binary-arm64/Packages
gzip -k dists/stable/main/binary-arm64/Packages

apt-ftparchive release dists/stable > dists/stable/Release
gpg --default-key <release-key> -abs -o dists/stable/Release.gpg dists/stable/Release
gpg --default-key <release-key> --clearsign -o dists/stable/InRelease dists/stable/Release
```

Customers then add the repo:

```bash
curl -fsSL https://0trustvpn.com/apt-pubkey.asc | sudo tee /etc/apt/keyrings/0trust.asc
echo "deb [signed-by=/etc/apt/keyrings/0trust.asc] https://apt.0trustvpn.com/ stable main" \
    | sudo tee /etc/apt/sources.list.d/0trust.list
sudo apt-get update
sudo apt-get install 0trust
```

The APT repo is **strongly recommended once you have >50 customers** because it amortizes the "release a new version" pain — bump the .deb, re-run apt-ftparchive, customers get the update on their next `apt update`.

## Distribution checklist

For the 0.1.0 launch, publish:

- [ ] `0trust_0.1.0_amd64.deb` + `.asc`
- [ ] `0trust_0.1.0_arm64.deb` + `.asc`
- [ ] `0trust-0.1.0-x86_64.AppImage` + `.asc`
- [ ] `0trust-0.1.0-aarch64.AppImage` + `.asc` (optional; depends on demand)

All at `https://0trustvpn.com/releases/0.1.0/`. Update `web/download.html` with the new Linux entries.
