// RouterTop — menu bar app showing which device on your Wi-Fi uses the most internet right now.
import AppKit
import ServiceManagement

// MARK: - Credentials (Keychain) and settings (UserDefaults)

enum Keychain {
    static let service = "RouterTop"
    static let legacyService = "router-top"   // saved by the router-top command-line tool

    static func load(service: String = service) -> (user: String, password: String)? {
        let q: [CFString: Any] = [kSecClass: kSecClassGenericPassword, kSecAttrService: service,
                                  kSecReturnAttributes: true, kSecReturnData: true,
                                  kSecMatchLimit: kSecMatchLimitOne]
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess,
              let d = out as? [CFString: Any], let data = d[kSecValueData] as? Data,
              let pw = String(data: data, encoding: .utf8) else { return nil }
        let acct = d[kSecAttrAccount] as? String ?? ""
        return (acct.isEmpty || acct == "router" ? "admin" : acct, pw)
    }

    static func save(user: String, password: String) {
        delete()
        let q: [CFString: Any] = [kSecClass: kSecClassGenericPassword, kSecAttrService: service,
                                  kSecAttrAccount: user, kSecValueData: Data(password.utf8)]
        SecItemAdd(q as CFDictionary, nil)
    }

    static func delete() {
        SecItemDelete([kSecClass: kSecClassGenericPassword, kSecAttrService: service] as CFDictionary)
    }
}

enum Settings {
    static var host: String {
        get { UserDefaults.standard.string(forKey: "host") ?? "192.168.1.1" }
        set { UserDefaults.standard.set(newValue, forKey: "host") }
    }
    static var showTopDevice: Bool {
        get { UserDefaults.standard.object(forKey: "showTopDevice") as? Bool ?? true }
        set { UserDefaults.standard.set(newValue, forKey: "showTopDevice") }
    }
    // Identity of the router the user set up. The password is only sent to that router,
    // so another network's 192.168.1.1 (café, hotel, a friend's house) never receives it.
    // Primary check: the router's RSA public key. Another device can copy the key but
    // can't decrypt with it. Fallback: its MAC address, in case the router made a new key on reboot.
    static var routerKey: String? {
        get { UserDefaults.standard.string(forKey: "routerKey") }
        set { UserDefaults.standard.set(newValue, forKey: "routerKey") }
    }
    static var routerMAC: String? {
        get { UserDefaults.standard.string(forKey: "routerMAC") }
        set { UserDefaults.standard.set(newValue, forKey: "routerMAC") }
    }
    static func forgetRouterIdentity() { routerKey = nil; routerMAC = nil }
    /// TP-Link allows one admin login at a time. When on, RouterTop logs out whoever is
    /// logged in (like the router page's "force log out"); when off, it waits for them.
    static var takeOver: Bool {
        get { UserDefaults.standard.object(forKey: "takeOver") as? Bool ?? true }
        set { UserDefaults.standard.set(newValue, forKey: "takeOver") }
    }
}

/// Looks up the MAC address of a host on the local network from the ARP table.
func macAddress(of host: String) -> String? {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/usr/sbin/arp")
    p.arguments = ["-n", host]
    let pipe = Pipe()
    p.standardOutput = pipe
    p.standardError = Pipe()
    guard (try? p.run()) != nil else { return nil }
    p.waitUntilExit()
    let out = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    guard let mac = RouterClient.match(#" at ([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5}) "#, in: out) else { return nil }
    // arp drops leading zeros ("d8:7:b6…"); normalise to "d8:07:b6…"
    return mac.split(separator: ":").map { $0.count == 1 ? "0" + $0 : String($0) }.joined(separator: ":").lowercased()
}

// MARK: - Formatting

func formatBytes(_ b: Double, perSecond: Bool = false, compact: Bool = false) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"]
    var v = b, i = 0
    while v >= 1024 && i < units.count - 1 { v /= 1024; i += 1 }
    if compact && i == 0 { v /= 1024; i = 1 }                     // menu bar: never show bytes
    let num = i == 0 || (compact && v >= 100) ? String(format: "%.0f", v) : String(format: "%.1f", v)
    return "\(num) \(units[i])" + (perSecond ? "/s" : "")
}

// MARK: - Monitor: polls the router and computes per-device speed

struct DeviceRow {
    let name: String
    let ip: String
    let rate: Double     // bytes per second, averaged over `window`
    let total: Int64     // bytes counted by the router so far
}

final class Monitor {
    enum State: Equatable {
        case needsSetup
        case connecting
        case running
        case paused(String)
        case failed(String)
    }

    static let window: TimeInterval = 10   // router refreshes its counters about every 10 s

    private(set) var state: State = .needsSetup
    private(set) var rows: [DeviceRow] = []
    var onUpdate: () -> Void = {}
    var onLoginRejected: (String) -> Void = { _ in }

    private var client: RouterClient?
    private var credentials: (user: String, password: String)?
    private var history: [String: [(t: TimeInterval, bytes: Int64)]] = [:]
    private var busy = false
    private var nextAttempt = Date.distantPast
    private(set) var userPaused = false

    var totalRate: Double { rows.reduce(0) { $0 + $1.rate } }

    func configure(user: String, password: String) {
        credentials = (user, password)
        resetConnection()
        state = .connecting
        nextAttempt = .distantPast
        onUpdate()
    }

    func setPaused(_ paused: Bool, reason: String = "Paused") {
        userPaused = paused
        if paused {
            let c = client
            client = nil
            Task { await c?.logout() }
            state = .paused(reason)
        } else {
            state = credentials == nil ? .needsSetup : .connecting
            nextAttempt = .distantPast
        }
        onUpdate()
    }

    func logout() async {
        await client?.logout()
        client = nil
    }

    private func resetConnection() {
        let c = client
        client = nil
        history = [:]
        rows = []
        Task { await c?.logout() }
    }

    /// Called every couple of seconds from the main run loop.
    func tick() {
        guard !busy, !userPaused, credentials != nil, Date() >= nextAttempt else { return }
        busy = true
        Task { @MainActor in
            await self.step()
            self.busy = false
            self.onUpdate()
        }
    }

    @MainActor
    private func step() async {
        guard let creds = credentials else { state = .needsSetup; return }
        do {
            if client == nil {
                let c = RouterClient(host: Settings.host)
                // TP-Link allows one admin at a time. Unless "Take Over Router Login" is on,
                // wait for whoever is logged in to the router page instead of kicking them out.
                if !Settings.takeOver, await c.someoneLoggedIn() {
                    state = .paused("Router page is in use; will resume after it logs out")
                    nextAttempt = Date().addingTimeInterval(15)
                    return
                }
                // Only send the password to the router the user set up.
                let key = try await c.publicKey().n
                let mac = macAddress(of: Settings.host)          // the requests above refreshed the ARP entry
                // A saved password only goes to a router with the exact saved key. A MAC address
                // can be spoofed, so a matching MAC is used only to word the message.
                let firstLogin = Settings.routerKey == nil
                guard firstLogin || Settings.routerKey == key else {
                    let sameHardware = mac != nil && mac == Settings.routerMAC
                    state = .paused(sameHardware
                        ? "Your router's security key changed (after a restart?). Open Router Settings and click Save to confirm. Password not sent."
                        : "Not your saved router (different network?). Your password was not sent.")
                    nextAttempt = Date().addingTimeInterval(30)
                    return
                }
                state = .connecting
                onUpdate()
                try await c.login(user: creds.user, password: creds.password, expectedKey: key)
                Settings.routerKey = key                          // remember (or refresh) after a good login
                if let mac { Settings.routerMAC = mac }
                if !(try await c.statsEnabled()) { try await c.enableStats() }
                client = c
            }
            let samples = try await client!.traffic()
            record(samples)
            state = .running
        } catch RouterError.badLogin {
            client = nil
            nextAttempt = .distantFuture          // stop retrying until the settings change
            state = .failed("Wrong email/username or password")
            onLoginRejected(RouterError.badLogin.localizedDescription)
        } catch {
            client = nil
            nextAttempt = Date().addingTimeInterval(10)
            state = .failed(error.localizedDescription)
        }
    }

    private func record(_ samples: [DeviceSample]) {
        let now = Date().timeIntervalSince1970
        var out: [DeviceRow] = []
        for s in samples {
            var h = history[s.key] ?? []
            if let last = h.last, s.total < last.bytes { h.removeAll() }   // counter reset
            h.append((now, s.total))
            while h.count > 2 && now - h[1].t >= Monitor.window { h.removeFirst() }
            history[s.key] = h
            let dt = now - h[0].t
            let rate = dt > 0.5 ? Double(s.total - h[0].bytes) / dt : 0
            out.append(DeviceRow(name: s.name, ip: s.ip, rate: max(rate, 0), total: s.total))
        }
        rows = out.sorted { ($0.rate, $0.total) > ($1.rate, $1.total) }
    }
}

// MARK: - App

final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    var statusItem: NSStatusItem!
    let menu = NSMenu()
    let monitor = Monitor()
    var timer: Timer?
    var sigterm: DispatchSourceSignal?

    func applicationDidFinishLaunching(_ n: Notification) {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        statusItem.button?.imagePosition = .imageLeading
        menu.delegate = self
        menu.autoenablesItems = false
        statusItem.menu = menu

        // Log out of the router even when stopped with `kill`/`pkill` (SIGTERM), not just Quit,
        // so a stale session doesn't hold the router's single admin slot.
        signal(SIGTERM, SIG_IGN)
        let term = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        term.setEventHandler { NSApp.terminate(nil) }
        term.resume()
        sigterm = term

        monitor.onUpdate = { [weak self] in self?.refreshUI() }
        monitor.onLoginRejected = { [weak self] msg in self?.showLoginError(msg) }

        // Poll on the common run loop mode so numbers keep updating while the menu is open.
        let t = Timer(timeInterval: 2, repeats: true) { [weak self] _ in self?.monitor.tick() }
        RunLoop.main.add(t, forMode: .common)
        timer = t

        if let creds = Keychain.load() {
            monitor.configure(user: creds.user, password: creds.password)
        } else if let legacy = Keychain.load(service: Keychain.legacyService) {
            // Reuse what the router-top command-line tool saved (macOS asks once).
            Keychain.save(user: legacy.user, password: legacy.password)
            monitor.configure(user: legacy.user, password: legacy.password)
        } else {
            DispatchQueue.main.async { self.showSettings() }
        }
        refreshUI()
        monitor.tick()
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        showSettings()
        return false
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        Task {
            await monitor.logout()                       // free the router's single admin slot
            NSApp.reply(toApplicationShouldTerminate: true)
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 3) { NSApp.reply(toApplicationShouldTerminate: true) }
        return .terminateLater
    }

    // MARK: Menu bar title

    func refreshUI() {
        guard let button = statusItem.button else { return }
        var symbol = "wifi"
        var text = ""
        switch monitor.state {
        case .running:
            if Settings.showTopDevice, let top = monitor.rows.first, top.rate >= 1024 {
                text = "\(String(top.name.prefix(12))) \(formatBytes(top.rate, perSecond: true, compact: true))"
            } else {
                text = formatBytes(monitor.totalRate, perSecond: true, compact: true)
            }
        case .connecting: text = "…"
        case .paused: symbol = "pause.circle"
        case .needsSetup, .failed: symbol = "wifi.exclamationmark"
        }
        button.image = NSImage(systemSymbolName: symbol, accessibilityDescription: "RouterTop")
        button.attributedTitle = NSAttributedString(
            string: text.isEmpty ? "" : " " + text,
            attributes: [.font: NSFont.monospacedDigitSystemFont(ofSize: NSFont.systemFontSize, weight: .regular)])
        if menuIsOpen { buildMenu() }
    }

    // MARK: Menu

    var menuIsOpen = false
    func menuWillOpen(_ menu: NSMenu) { menuIsOpen = true; buildMenu() }
    func menuDidClose(_ menu: NSMenu) { menuIsOpen = false }

    func buildMenu() {
        menu.removeAllItems()
        let digits = NSFont.monospacedDigitSystemFont(ofSize: NSFont.systemFontSize, weight: .regular)
        let small = NSFont.systemFont(ofSize: NSFont.smallSystemFontSize)

        func info(_ s: String, bold: Bool = false) {
            let mi = NSMenuItem(title: s, action: nil, keyEquivalent: "")
            mi.attributedTitle = NSAttributedString(string: s, attributes: [
                .font: bold ? NSFont.boldSystemFont(ofSize: NSFont.systemFontSize) : small,
                .foregroundColor: bold ? NSColor.labelColor : NSColor.secondaryLabelColor])
            mi.isEnabled = false
            menu.addItem(mi)
        }

        switch monitor.state {
        case .running:
            info("Right now: \(formatBytes(monitor.totalRate, perSecond: true)) across \(monitor.rows.count) devices", bold: true)
            info("Speed averaged over the last \(Int(Monitor.window))s · Total = counted by router")
            menu.addItem(.separator())
            let para = NSMutableParagraphStyle()
            para.tabStops = [NSTextTab(textAlignment: .right, location: 330),
                             NSTextTab(textAlignment: .right, location: 420)]
            let top = max(monitor.rows.first?.rate ?? 0, 1)
            for (i, r) in monitor.rows.enumerated() {
                let share = r.rate / top
                let dot: NSColor = r.rate < 1024 ? .tertiaryLabelColor
                    : share > 0.66 ? .systemRed : share > 0.33 ? .systemOrange : .systemGreen
                let s = NSMutableAttributedString()
                s.append(NSAttributedString(string: "● ", attributes: [.foregroundColor: dot, .font: digits]))
                s.append(NSAttributedString(string: String(r.name.prefix(24)), attributes: [
                    .font: i == 0 && r.rate >= 1024 ? NSFont.boldSystemFont(ofSize: NSFont.systemFontSize) : digits]))
                s.append(NSAttributedString(string: "  \(r.ip)", attributes: [.font: small, .foregroundColor: NSColor.secondaryLabelColor]))
                s.append(NSAttributedString(string: "\t\(formatBytes(r.rate, perSecond: true))\t\(formatBytes(Double(r.total)))",
                                            attributes: [.font: digits]))
                s.addAttribute(.paragraphStyle, value: para, range: NSRange(location: 0, length: s.length))
                let mi = NSMenuItem(title: r.name, action: #selector(noop), keyEquivalent: "")
                mi.target = self
                mi.attributedTitle = s
                mi.toolTip = "\(r.name) · \(r.ip)"
                menu.addItem(mi)
            }
            if monitor.rows.isEmpty { info("No devices reported yet") }
        case .connecting: info("Connecting to \(Settings.host)…", bold: true)
        case .needsSetup: info("Set up your router to start", bold: true)
        case .paused(let why): info(why, bold: true)
        case .failed(let why): info("⚠︎ \(why)", bold: true)
        }

        menu.addItem(.separator())
        func add(_ title: String, _ sel: Selector, key: String = "", state: Bool? = nil) {
            let mi = NSMenuItem(title: title, action: sel, keyEquivalent: key)
            mi.target = self
            if let state { mi.state = state ? .on : .off }
            menu.addItem(mi)
        }
        add("Show Top Device in Menu Bar", #selector(toggleTopDevice), state: Settings.showTopDevice)
        add("Take Over Router Login", #selector(toggleTakeOver), state: Settings.takeOver)
        add(monitor.userPaused ? "Resume Monitoring" : "Pause Monitoring", #selector(togglePause))
        add("Open Router Page…", #selector(openRouterPage))
        menu.addItem(.separator())
        add("Router Settings…", #selector(showSettings), key: ",")
        add("Launch at Login", #selector(toggleLogin), state: SMAppService.mainApp.status == .enabled)
        add("About RouterTop", #selector(openAbout))
        menu.addItem(.separator())
        add("Quit RouterTop", #selector(quit), key: "q")
    }

    @objc func noop() {}

    @objc func toggleTopDevice() {
        Settings.showTopDevice.toggle()
        refreshUI()
    }

    @objc func toggleTakeOver() {
        Settings.takeOver.toggle()
        if Settings.takeOver, case .paused = monitor.state, !monitor.userPaused { monitor.setPaused(false) }
        refreshUI()
    }

    @objc func togglePause() {
        monitor.setPaused(!monitor.userPaused)
    }

    @objc func openRouterPage() {
        // The router allows one admin login at a time, so step aside first.
        monitor.setPaused(true, reason: "Paused while you use the router page. Click Resume when done.")
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
            NSWorkspace.shared.open(URL(string: "http://\(Settings.host)")!)
        }
    }

    @objc func toggleLogin() {
        do {
            if SMAppService.mainApp.status == .enabled { try SMAppService.mainApp.unregister() }
            else { try SMAppService.mainApp.register() }
        } catch { NSSound.beep() }
    }

    @objc func openAbout() {
        NSWorkspace.shared.open(URL(string: "https://github.com/mohamedhadia/RouterTop")!)
    }

    @objc func quit() { NSApp.terminate(nil) }

    // MARK: Settings dialog

    @objc func showSettings() {
        let saved = Keychain.load()
        let alert = NSAlert()
        alert.icon = NSApp.applicationIconImage
        alert.messageText = "RouterTop Settings"
        alert.informativeText = """
        RouterTop lives in your menu bar and shows which device on your network uses the most internet.

        Enter the details you use to log in to your router's web page. If you log in with an email (TP-Link ID), enter that email. Otherwise leave "admin".
        """

        func label(_ s: String) -> NSTextField {
            let l = NSTextField(labelWithString: s)
            l.alignment = .right
            return l
        }
        let hostField = NSTextField(string: Settings.host)
        let userField = NSTextField(string: saved?.user ?? "admin")
        userField.placeholderString = "admin, or your TP-Link ID email"
        let passField = NSSecureTextField(string: saved?.password ?? "")
        for f in [hostField, userField, passField] { f.widthAnchor.constraint(equalToConstant: 240).isActive = true }

        let grid = NSGridView(views: [[label("Router address:"), hostField],
                                      [label("Email or username:"), userField],
                                      [label("Password:"), passField]])
        grid.rowSpacing = 8
        grid.columnSpacing = 8
        grid.frame = NSRect(x: 0, y: 0, width: 380, height: 90)
        alert.accessoryView = grid
        alert.addButton(withTitle: "Save")
        alert.addButton(withTitle: "Cancel")
        if saved != nil { alert.addButton(withTitle: "Forget Password") }
        alert.window.initialFirstResponder = saved == nil ? passField : hostField

        NSApp.activate(ignoringOtherApps: true)
        switch alert.runModal() {
        case .alertFirstButtonReturn:
            let host = hostField.stringValue.trimmingCharacters(in: .whitespaces)
            let user = userField.stringValue.trimmingCharacters(in: .whitespaces)
            let pass = passField.stringValue
            guard !host.isEmpty, !pass.isEmpty else { NSSound.beep(); return }
            Settings.host = host
            Settings.forgetRouterIdentity()   // the user just confirmed this router; learn it again
            Keychain.save(user: user.isEmpty ? "admin" : user, password: pass)
            if monitor.userPaused { monitor.setPaused(false) }
            monitor.configure(user: user.isEmpty ? "admin" : user, password: pass)
        case .alertThirdButtonReturn:
            Keychain.delete()
        default:
            break
        }
    }

    func showLoginError(_ msg: String) {
        let alert = NSAlert()
        alert.messageText = "RouterTop couldn't log in"
        alert.informativeText = msg
        alert.addButton(withTitle: "Open Settings")
        alert.addButton(withTitle: "Later")
        NSApp.activate(ignoringOtherApps: true)
        if alert.runModal() == .alertFirstButtonReturn { showSettings() }
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
