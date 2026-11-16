<p align="center">
  <img src="docs/icon.png" width="128" alt="RouterTop icon">
</p>

<h1 align="center">RouterTop</h1>

<p align="center">
  <b>See which device on your Wi-Fi is using the internet right now, from your Mac's menu bar.</b><br>
  A tiny, free, open-source menu bar app for TP-Link Archer VR-series routers.
</p>

<p align="center">
  <a href="https://github.com/mohamedhadia/RouterTop/releases/latest"><img src="https://img.shields.io/github/v/release/mohamedhadia/RouterTop?label=download" alt="Latest release"></a>
  <img src="https://img.shields.io/badge/macOS-13%2B-blue" alt="macOS 13+">
  <img src="https://img.shields.io/badge/Apple%20Silicon%20%2B%20Intel-universal-success" alt="Universal">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-lightgrey" alt="MIT"></a>
</p>

---

## The problem

The internet suddenly gets slow and you want to know **who's using it**: a phone downloading an update, a TV streaming in 4K, a laptop syncing photos. Your router knows, but the answer is buried in a web page you have to log in to and refresh by hand.

## What RouterTop does

RouterTop reads your router's traffic statistics every 2 seconds and shows:

- **In the menu bar:** the device using the most right now and its speed, for example `iPhone 73 KB/s`. You can switch this to show total speed instead.
- **In the menu:** every connected device, sorted by current speed, with its IP address, current speed and total data used. A colored dot marks the heavy users (🔴 heaviest, 🟠 medium, 🟢 light).

```
Right now: 1.2 MB/s across 10 devices
──────────────────────────────────────────────
● Living-Room-TV  192.168.1.110    1.0 MB/s    9.8 GB
● iPhone          192.168.1.103   73.1 KB/s   12.4 MB
● realme-6        192.168.1.109   16.3 KB/s    1.5 MB
● iPad            192.168.1.108       0 B/s   49.6 KB
```

Speeds are averaged over 10 seconds, because the router refreshes its counters in steps.

## Supported routers

TP-Link routers with the **Archer VR** web interface (VDSL/ADSL modem routers), such as the **Archer VR600** (tested), VR300, VR400, VR900 and VR2100. Both login types work:

- **Password only** (username `admin`)
- **TP-Link ID** (email + password)

Other routers aren't supported yet. Contributions welcome.

## Install

### Option 1: One-line install (easiest)

```bash
curl -fsSL https://raw.githubusercontent.com/mohamedhadia/RouterTop/main/install.sh | zsh
```

### Option 2: Download the DMG

1. Download **`RouterTop.dmg`** from the [latest release](https://github.com/mohamedhadia/RouterTop/releases/latest).
2. Drag **RouterTop** into **Applications** and open it.

> **"Apple could not verify RouterTop…"**
> RouterTop is free and isn't notarized with a paid Apple Developer account. To allow it, open **System Settings → Privacy & Security** and click **Open Anyway**, or run:
> `xattr -dr com.apple.quarantine /Applications/RouterTop.app`

### First launch

1. RouterTop opens its **Settings**. Enter:
   - **Router address:** usually `192.168.1.1`, or `192.168.0.1` on some networks.
   - **Email or username:** your TP-Link ID email if you log in with one, otherwise `admin`.
   - **Password:** the same password you use on the router's web page.
2. If macOS asks to let RouterTop **find devices on your local network**, click **Allow**. RouterTop needs this to talk to your router.
3. Click the Wi-Fi icon in the menu bar to see your devices.

RouterTop turns on the router's **Traffic Statistics** feature automatically if it's off.

## Menu options

| Item | What it does |
|---|---|
| Show Top Device in Menu Bar | Shows the top device and its speed, or (when off) the total speed only |
| Pause / Resume Monitoring | Logs out of the router and stops polling |
| Open Router Page… | Pauses RouterTop and opens the router's web page in your browser |
| Router Settings… | Changes the router address or login, or forgets the saved password |
| Launch at Login | Starts RouterTop automatically |

## Good to know

- **One admin login at a time.** TP-Link routers allow only one logged-in admin. RouterTop never kicks you out: if someone is logged in to the router's web page, RouterTop waits until they log out. Use **Open Router Page…** to pause RouterTop automatically.
- **Some routers count one direction only.** Many VR-series firmwares report only one direction (mostly downloads) when hardware NAT acceleration is on. That's enough to find the heavy user. Turning off **NAT Boost / Hardware NAT** on the router may enable full counting, at a small cost in top speed.
- **"Total"** is the data counted by the router since its Traffic Statistics were last reset (or the router restarted).

## Privacy & security

- Your password is stored in the **macOS Keychain**, never in plain text.
- RouterTop talks **only to your router**, on your local network. No internet access, no analytics, no data collection.
- The login is encrypted the same way the router's own web page does it (RSA, using the key the router provides).
- **Your password only goes to your router.** On the first successful login, RouterTop remembers your router's RSA public key and MAC address. On any other network (a café, a hotel, a friend's house), whatever answers at `192.168.1.1` won't match, so RouterTop pauses and doesn't send your password. If you replace your router, re-save **Router Settings**.
- The full source is in [`Sources/`](Sources/), about 650 lines.

## Command-line version

Prefer the terminal? [`cli/router_top.py`](cli/router_top.py) is the same monitor as a live table (Python 3, no dependencies):

```bash
python3 cli/router_top.py              # --host, --interval, --user, --raw, --forget
```

The menu bar app reuses a password the CLI saved in Keychain (macOS asks once).

## Build from source

Requirements: macOS 13+ and Xcode Command Line Tools (`xcode-select --install`).

```bash
git clone https://github.com/mohamedhadia/RouterTop.git
cd RouterTop
./scripts/test.sh             # unit checks (RSA verified against OpenSSL, parser)
./scripts/build.sh --install  # universal app → /Applications, then launches it
```

## Releasing

Tag a version and push. GitHub Actions runs the tests, builds the universal app and publishes `RouterTop.dmg` and `RouterTop.zip`:

```bash
git tag v1.1.0 && git push origin v1.1.0
```

## How it works

1. `POST /cgi/getParm` returns the router's RSA public key and login mode (`userSetting=2` means TP-Link ID).
2. The username or email and the Base64 password are RSA-encrypted (PKCS#1 v1.5) and sent to `/cgi/login`. That gives a session cookie, and the session token comes from the main page.
3. `POST /cgi?5` with `[STAT_ENTRY#…]` returns per-device byte counters (`totalBytes`, or `totalBytesRx` + `totalBytesTx`).
4. RouterTop keeps a 10-second history per device and computes the speed from the change in the counters.

## License

[MIT](LICENSE)
