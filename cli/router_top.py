#!/usr/bin/env python3
"""router-top: live "who is using the internet" view for TP-Link Archer VR-series routers.

Logs into the router's web admin (same API the web page uses), reads the
Traffic Statistics table every few seconds, and shows devices sorted by
current speed. Python 3 standard library only.

    python3 router_top.py                  # router at 192.168.1.1
    python3 router_top.py --host 192.168.0.1 --interval 3
    python3 router_top.py --forget         # delete the saved password

Note: TP-Link allows one admin login at a time, so while this runs the
router's web page will ask to "force log out". Ctrl+C logs out cleanly.
"""
import argparse, base64, getpass, http.cookiejar, json, os, re, secrets, shutil, signal
import subprocess, sys, time, urllib.request

KEYCHAIN_SERVICE = "router-top"

# ---------------------------------------------------------------- router API

class Router:
    def __init__(self, host):
        self.base = f"http://{host}"
        self.jar = http.cookiejar.CookieJar()
        self.http = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.token = None

    def _req(self, path, data=None, method="POST"):
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Referer", self.base + "/")
        req.add_header("Content-Type", "text/plain")
        if self.token:
            req.add_header("TokenID", self.token)
        with self.http.open(req, timeout=8) as r:
            return r.read().decode("utf-8", "replace")

    @staticmethod
    def _rsa(text, n_hex, e_hex):
        """PKCS#1 v1.5 (type 2) RSA encryption, matching the router's encrypt.js."""
        n, e = int(n_hex, 16), int(e_hex, 16)
        k = (n.bit_length() + 7) // 8
        msg = text.encode()
        pad = b""
        while len(pad) < k - 3 - len(msg):
            b = secrets.token_bytes(1)
            if b != b"\x00":
                pad += b
        block = b"\x00\x02" + pad + b"\x00" + msg
        return format(pow(int.from_bytes(block, "big"), e, n), "x").zfill(k * 2)

    def uses_email_login(self):
        """userSetting=2 means the router is bound to a TP-Link ID (email + password)."""
        return re.search(r"userSetting=(\d+)", self._req("/cgi/getParm")).group(1) == "2"

    def public_key(self):
        parm = self._req("/cgi/getParm")
        e = re.search(r'ee="([0-9a-fA-F]+)"', parm).group(1)
        n = re.search(r'nn="([0-9a-fA-F]+)"', parm).group(1)
        return n.lower(), e

    def login(self, password, user="admin", expected_key=None):
        n, e = self.public_key()
        if expected_key and n != expected_key:
            raise RuntimeError("router key changed during login")
        name = self._rsa(user, n, e)
        auth = self._rsa(base64.b64encode(password.encode()).decode(), n, e)
        self._req(f"/cgi/login?UserName={name}&Passwd={auth}&Action=1&LoginStatus=0")
        if not any(c.name == "JSESSIONID" and c.value not in ("", "deleted") for c in self.jar):
            raise PermissionError("Wrong email/password (or the router locked logins for a few minutes after too many tries).")
        page = self._req("/", method="GET")
        m = re.search(r'var token="([^"]+)"', page)
        if not m:
            raise PermissionError("Logged in but got no session token. Try again in a minute.")
        self.token = m.group(1)

    def logout(self):
        try:
            self._req("/cgi?8", b"[/cgi/logout#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n")
        except Exception:
            pass

    @staticmethod
    def _parse(text):
        """Parse the router's '[id]idx\\nkey=value\\n' blocks into a list of dicts."""
        rows, cur = [], None
        for line in text.splitlines():
            if line.startswith("[error]"):
                code = line[7:].strip()
                if code not in ("", "0"):
                    raise RuntimeError(f"router returned error {code}")
            elif line.startswith("["):
                cur = {}
                rows.append(cur)
            elif "=" in line and cur is not None:
                k, v = line.split("=", 1)
                cur[k] = v
        return rows

    def stats_enabled(self):
        r = self._parse(self._req("/cgi?1", b"[STAT_CFG#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n"))
        return bool(r) and r[0].get("enable") == "1"

    def enable_stats(self):
        self._req("/cgi?2", b"[STAT_CFG#0,0,0,0,0,0#0,0,0,0,0,0]0,1\r\nenable=1\r\n")

    def traffic(self):
        return self._parse(self._req("/cgi?5", b"[STAT_ENTRY#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n"))

    def hosts(self):
        rows = self._parse(self._req(
            "/cgi?5", b"[LAN_HOST_ENTRY#0,0,0,0,0,0#0,0,0,0,0,0]0,3\r\nIPAddress\r\nMACAddress\r\nhostName\r\n"))
        return {r.get("IPAddress"): r for r in rows}

# ---------------------------------------------------------------- password

def keychain_get():
    """Returns (username, password) saved in Keychain, or (None, None)."""
    r = subprocess.run(["security", "find-generic-password", "-s", KEYCHAIN_SERVICE, "-w"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return None, None
    a = subprocess.run(["security", "find-generic-password", "-s", KEYCHAIN_SERVICE],
                       capture_output=True, text=True)
    m = re.search(r'"acct"<blob>="([^"]*)"', a.stdout)
    user = m.group(1) if m and m.group(1) != "router" else "admin"
    return user, r.stdout.rstrip("\n")

def keychain_set(user, pw):
    keychain_delete()
    # "-w" as the last option makes `security` read the password from stdin,
    # so it never appears in the process list.
    subprocess.run(["security", "add-generic-password", "-U", "-s", KEYCHAIN_SERVICE, "-a", user, "-w"],
                   input=f"{pw}\n{pw}\n", capture_output=True, text=True)

def keychain_delete():
    subprocess.run(["security", "delete-generic-password", "-s", KEYCHAIN_SERVICE], capture_output=True)

# ---------------------------------------------------------------- router identity

PIN_FILE = os.path.expanduser("~/.config/router-top/router-identity.json")

def router_mac(host):
    """MAC address of the router from the ARP table (normalised, lowercase)."""
    out = subprocess.run(["/usr/sbin/arp", "-n", host], capture_output=True, text=True).stdout
    m = re.search(r" at ([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5}) ", out)
    return ":".join(p.zfill(2) for p in m.group(1).split(":")).lower() if m else None

# Identity of the router the password was saved for. Primary check is its RSA public
# key (another device can copy it but can't decrypt with it); the MAC address is a
# fallback in case the router generates a new key after a reboot.
def load_pin():
    try:
        return json.load(open(PIN_FILE))
    except (OSError, ValueError):
        return {}

def save_pin(key, mac):
    os.makedirs(os.path.dirname(PIN_FILE), exist_ok=True)
    with open(PIN_FILE, "w") as f:
        json.dump({"key": key, "mac": mac}, f)

# ---------------------------------------------------------------- display

def clean(s):
    """Strip control characters (e.g. terminal escape codes) from router-supplied text."""
    return "".join(ch for ch in str(s) if ch.isprintable())

def ip_str(v):
    if v and v.isdigit():                       # some firmwares send the IP as an integer
        n = int(v)
        return ".".join(str((n >> s) & 255) for s in (24, 16, 8, 0))
    return v or "?"

WINDOW = 10.0   # seconds of history used to compute "NOW" speed

def entry_total(e):
    """Total bytes for one device. Firmwares differ: some send totalBytes,
    others split it into totalBytesRx + totalBytesTx."""
    if e.get("totalBytes", "").isdigit():
        return int(e["totalBytes"])
    return sum(int(e.get(k, "0") or 0) for k in ("totalBytesRx", "totalBytesTx") if e.get(k, "0").isdigit())

def human(nbytes, per_sec=False):
    units = ["B", "KB", "MB", "GB", "TB"]
    v = float(nbytes)
    for u in units:
        if v < 1024 or u == units[-1]:
            s = f"{v:.0f} {u}" if u == "B" else f"{v:.1f} {u}"
            return s + ("/s" if per_sec else "")
        v /= 1024

BOLD, DIM, GREEN, YELLOW, RED, RESET = "\033[1m", "\033[2m", "\033[32m", "\033[33m", "\033[31m", "\033[0m"

def render(rows, interval, host, started):
    cols = shutil.get_terminal_size((100, 30)).columns
    bar_w = max(10, cols - 92)
    top = max((r["rate"] for r in rows), default=0) or 1
    total_rate = sum(r["rate"] for r in rows)
    out = ["\033[H\033[2J",
           f"{BOLD}router-top{RESET}  {host}   every {interval}s   "
           f"running {int(time.time() - started)}s   {DIM}Ctrl+C to quit{RESET}\n",
           f"Total right now: {BOLD}{human(total_rate, True)}{RESET}\n\n",
           f"{BOLD}{'DEVICE':<26} {'IP':<15} {'NOW':>12} {'SINCE START':>12} {'ROUTER TOTAL':>13}  {RESET}\n"]
    for r in rows:
        share = r["rate"] / top
        color = RED if share > 0.66 and r["rate"] > 100_000 else YELLOW if share > 0.33 else GREEN
        bar = color + "█" * int(share * bar_w) + RESET if r["rate"] > 0 else ""
        out.append(f"{r['name'][:26]:<26} {r['ip']:<15} {human(r['rate'], True):>12} "
                   f"{human(r['session']):>12} {human(r['total']):>13}  {bar}\n")
    if not rows:
        out.append(f"{DIM}No devices reported yet. Waiting for the router to collect data…{RESET}\n")
    out.append(f"\n{DIM}NOW = average speed over the last {WINDOW:.0f}s, as counted by the router. "
               f"Your router reports one direction only (mostly downloads).{RESET}\n")
    sys.stdout.write("".join(out))
    sys.stdout.flush()

# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description="Live per-device internet usage from a TP-Link Archer VR router.")
    ap.add_argument("--host", default="192.168.1.1")
    ap.add_argument("--interval", type=float, default=2.0)
    ap.add_argument("--user", help="login email (TP-Link ID) or username; asked automatically if needed")
    ap.add_argument("--raw", action="store_true", help="print the router's raw statistics responses (for troubleshooting)")
    ap.add_argument("--forget", action="store_true", help="delete the password saved in Keychain")
    args = ap.parse_args()

    if args.forget:
        keychain_delete()
        try:
            os.remove(PIN_FILE)
        except OSError:
            pass
        print("Saved router password removed from Keychain.")
        return

    router = Router(args.host)
    user, pw = keychain_get()
    from_keychain = bool(pw)
    if args.user and args.user != user:
        user, pw, from_keychain = args.user, None, False
    if not pw:
        if not user:
            try:
                email_mode = router.uses_email_login()
            except Exception as e:
                sys.exit(f"Could not reach the router at {args.host}: {e}")
            if email_mode:
                user = input("This router uses a TP-Link ID. Login email: ").strip()
            else:
                user = "admin"
        pw = getpass.getpass(f"Router admin password for {args.host} (typing is hidden, press Enter when done): ")

    # Only send a saved password to the router it was saved for, so another
    # network's 192.168.1.1 never receives it.
    try:
        key, _ = router.public_key()          # also refreshes the router's ARP entry
    except Exception as e:
        sys.exit(f"Could not reach the router at {args.host}: {e}")
    mac = router_mac(args.host)
    pin = load_pin()
    # A saved password only goes to a router with the exact saved key. A MAC address can be
    # spoofed, so it only changes the wording; the user must confirm a changed key.
    if from_keychain and pin.get("key") and pin["key"] != key:
        if mac is not None and pin.get("mac") == mac:
            print("Your router's security key changed (this can happen after a restart).")
        else:
            print("This doesn't look like your saved router (different network?).")
        if input("Send your saved password to this router? [y/N] ").strip().lower() != "y":
            sys.exit("Password not sent.")
    try:
        router.login(pw, user, expected_key=key)
        save_pin(key, mac or pin.get("mac"))
    except PermissionError as e:
        if from_keychain:
            keychain_delete()
        sys.exit(f"Login failed: {e}")
    except Exception as e:
        sys.exit(f"Could not reach the router at {args.host}: {e}")

    if not from_keychain:
        if input("Save this password in your macOS Keychain for next time? [y/N] ").strip().lower() == "y":
            keychain_set(user, pw)

    def bye(*_):
        router.logout()
        sys.stdout.write("\033[0m\nLogged out of the router.\n")
        sys.exit(0)
    signal.signal(signal.SIGINT, bye)
    signal.signal(signal.SIGTERM, bye)

    if args.raw:
        try:
            for label, body in [("STAT_CFG", b"[STAT_CFG#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n"),
                                ("STAT_ENTRY", b"[STAT_ENTRY#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n")]:
                print(f"===== {label} =====")
                print(router._req("/cgi?1" if label == "STAT_CFG" else "/cgi?5", body))
            print("===== STAT_ENTRY again after 5s =====")
            time.sleep(5)
            print(router._req("/cgi?5", b"[STAT_ENTRY#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n"))
        finally:
            router.logout()
        return

    if not router.stats_enabled():
        print("Traffic Statistics is off on the router. Turning it on…")
        router.enable_stats()
        time.sleep(1)

    names, names_at = {}, 0
    prev, first, started = {}, {}, time.time()
    while True:
        try:
            if time.time() - names_at > 30:
                names, names_at = router.hosts(), time.time()
            entries = router.traffic()
        except Exception as e:
            sys.stdout.write(f"\n{RED}Lost connection ({e}). Logging in again…{RESET}\n")
            time.sleep(2)
            try:
                router = Router(args.host)
                key, _ = router.public_key()
                pin = load_pin()
                mac = router_mac(args.host)
                if pin.get("key") == key:
                    router.login(pw, user, expected_key=key)
                    save_pin(key, mac or pin.get("mac"))
                else:
                    sys.exit(f"{RED}Router identity changed (different network or router restart). "
                             f"Password not sent. Run router-top again to confirm.{RESET}")
            except Exception:
                pass
            continue

        now = time.time()
        rows = []
        for e in entries:
            ip = ip_str(e.get("ipAddress"))
            mac = e.get("macAddress", "")
            key = mac or ip
            total = entry_total(e)
            # The router refreshes its counters in steps (STAT_CFG interval, ~10s),
            # so measure speed over a sliding window instead of between two polls.
            hist = prev.setdefault(key, [])
            if hist and total < hist[-1][1]:          # counter reset / wrapped
                hist.clear()
                first.pop(key, None)
            hist.append((now, total))
            while len(hist) > 2 and now - hist[1][0] >= WINDOW:
                hist.pop(0)
            t0, b0 = hist[0]
            rate = (total - b0) / (now - t0) if now - t0 > 0.5 else 0.0
            first.setdefault(key, total)
            h = names.get(ip) or next((v for v in names.values() if v.get("MACAddress", "").lower() == mac.lower()), {})
            name = e.get("hostName") or h.get("hostName") or ""
            if name in ("", "--", "*"):
                name = mac or "unknown device"
            rows.append({"name": clean(name), "ip": clean(ip), "rate": max(rate, 0),
                         "session": max(total - first[key], 0), "total": total})
        rows.sort(key=lambda r: (r["rate"], r["session"]), reverse=True)
        render(rows, args.interval, args.host, started)
        time.sleep(args.interval)

if __name__ == "__main__":
    main()
