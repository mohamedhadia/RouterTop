// Talks to a TP-Link Archer VR-series router the same way its web admin page does.
import Foundation
import Security

struct DeviceSample {
    let key: String      // MAC address (or IP if no MAC)
    let name: String
    let ip: String
    let total: Int64     // bytes counted by the router so far
}

enum RouterError: LocalizedError {
    case unreachable(String)
    case badLogin
    case noToken
    case otherAdminLoggedIn
    case router(String)

    var errorDescription: String? {
        switch self {
        case .unreachable(let why): return "Can't reach the router (\(why))."
        case .badLogin: return "Wrong email/username or password. After several wrong tries the router locks logins for a few minutes."
        case .noToken: return "Logged in, but the router didn't return a session token. Try again in a minute."
        case .otherAdminLoggedIn: return "Someone is logged in to the router's web page. RouterTop will resume when they log out."
        case .router(let code): return "The router returned error \(code)."
        }
    }
}

final class RouterClient {
    let host: String
    private let session: URLSession
    private var token: String?

    init(host: String) {
        self.host = host
        let cfg = URLSessionConfiguration.ephemeral          // own in-memory cookie jar
        cfg.timeoutIntervalForRequest = 8
        cfg.httpCookieAcceptPolicy = .always
        session = URLSession(configuration: cfg)
    }

    private var base: String { "http://\(host)" }

    // MARK: HTTP

    @discardableResult
    func request(_ path: String, body: String? = nil, method: String = "POST") async throws -> String {
        guard let url = URL(string: base + path) else { throw RouterError.unreachable("bad address") }
        var req = URLRequest(url: url)
        req.httpMethod = method
        req.setValue(base + "/", forHTTPHeaderField: "Referer")
        req.setValue("text/plain", forHTTPHeaderField: "Content-Type")
        if let token { req.setValue(token, forHTTPHeaderField: "TokenID") }
        if let body { req.httpBody = Data(body.utf8) }
        do {
            let (data, resp) = try await session.data(for: req)
            if let http = resp as? HTTPURLResponse, http.statusCode >= 400 {
                throw RouterError.router("HTTP \(http.statusCode)")
            }
            return String(decoding: data, as: UTF8.self)
        } catch let e as RouterError {
            throw e
        } catch {
            throw RouterError.unreachable(error.localizedDescription)
        }
    }

    // MARK: Session

    /// true when the router is bound to a TP-Link ID (login with email + password).
    func usesEmailLogin() async throws -> Bool {
        let parm = try await request("/cgi/getParm")
        return Self.match(#"userSetting=(\d+)"#, in: parm) == "2"
    }

    /// true when someone (other than us) is logged in to the web admin page.
    func someoneLoggedIn() async -> Bool {
        guard let s = try? await request("/cgi/getBusy") else { return false }
        return Self.match(#"isLogined=(\d+)"#, in: s) == "1"
    }

    func login(user: String, password: String) async throws {
        let parm = try await request("/cgi/getParm")
        guard let e = Self.match(#"ee="([0-9a-fA-F]+)""#, in: parm),
              let n = Self.match(#"nn="([0-9a-fA-F]+)""#, in: parm) else {
            throw RouterError.router("unsupported router (no login key)")
        }
        let name = try Self.rsaEncrypt(user, modulusHex: n, exponentHex: e)
        let auth = try Self.rsaEncrypt(Data(password.utf8).base64EncodedString(), modulusHex: n, exponentHex: e)
        try await request("/cgi/login?UserName=\(name)&Passwd=\(auth)&Action=1&LoginStatus=0")

        let cookies = session.configuration.httpCookieStorage?.cookies(for: URL(string: base)!) ?? []
        guard cookies.contains(where: { $0.name == "JSESSIONID" && !$0.value.isEmpty && $0.value != "deleted" }) else {
            throw RouterError.badLogin
        }
        let page = try await request("/", method: "GET")
        guard let t = Self.match(#"var token="([^"]+)""#, in: page) else { throw RouterError.noToken }
        token = t
    }

    func logout() async {
        guard token != nil else { return }
        _ = try? await request("/cgi?8", body: "[/cgi/logout#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n")
        token = nil
    }

    var isLoggedIn: Bool { token != nil }

    // MARK: Traffic statistics

    func statsEnabled() async throws -> Bool {
        let r = try Self.parse(await request("/cgi?1", body: "[STAT_CFG#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n"))
        return r.first?["enable"] == "1"
    }

    func enableStats() async throws {
        try await request("/cgi?2", body: "[STAT_CFG#0,0,0,0,0,0#0,0,0,0,0,0]0,1\r\nenable=1\r\n")
    }

    func traffic() async throws -> [DeviceSample] {
        let text = try await request("/cgi?5", body: "[STAT_ENTRY#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n")
        // If our session was kicked out (e.g. someone logged in to the web page),
        // the router answers with its login page instead of data.
        guard text.contains("[error]") else { token = nil; throw RouterError.router("session ended") }
        return try Self.parse(text).map { Self.sample(from: $0) }
    }

    // MARK: Parsing helpers (static so they can be unit-tested)

    /// Parses the router's "[id]idx\nkey=value\n…[error]0" format.
    static func parse(_ text: String) throws -> [[String: String]] {
        var rows: [[String: String]] = []
        for raw in text.split(whereSeparator: \.isNewline) {
            let line = String(raw)
            if line.hasPrefix("[error]") {
                let code = line.dropFirst(7).trimmingCharacters(in: .whitespaces)
                if !code.isEmpty && code != "0" { throw RouterError.router(code) }
            } else if line.hasPrefix("[") {
                rows.append([:])
            } else if let eq = line.firstIndex(of: "="), !rows.isEmpty {
                rows[rows.count - 1][String(line[..<eq])] = String(line[line.index(after: eq)...])
            }
        }
        return rows
    }

    static func sample(from e: [String: String]) -> DeviceSample {
        // Firmwares differ: some send totalBytes, others totalBytesRx + totalBytesTx.
        let total: Int64 = Int64(e["totalBytes"] ?? "")
            ?? ((Int64(e["totalBytesRx"] ?? "") ?? 0) + (Int64(e["totalBytesTx"] ?? "") ?? 0))
        let ip = ipString(e["ipAddress"] ?? "")
        let mac = e["macAddress"] ?? ""
        var name = e["hostName"] ?? ""
        if ["", "--", "*"].contains(name) { name = mac.isEmpty ? "Unknown device" : mac }
        return DeviceSample(key: mac.isEmpty ? ip : mac, name: name, ip: ip, total: total)
    }

    static func ipString(_ v: String) -> String {
        guard let n = UInt32(v) else { return v.isEmpty ? "?" : v }     // some firmwares send an integer
        return [24, 16, 8, 0].map { String((n >> UInt32($0)) & 255) }.joined(separator: ".")
    }

    static func match(_ pattern: String, in text: String) -> String? {
        guard let re = try? NSRegularExpression(pattern: pattern),
              let m = re.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)),
              let r = Range(m.range(at: 1), in: text) else { return nil }
        return String(text[r])
    }

    // MARK: RSA (PKCS#1 v1.5), matching the router's encrypt.js

    static func rsaEncrypt(_ text: String, modulusHex: String, exponentHex: String) throws -> String {
        func derLength(_ n: Int) -> [UInt8] {
            if n < 0x80 { return [UInt8(n)] }
            if n <= 0xFF { return [0x81, UInt8(n)] }
            return [0x82, UInt8(n >> 8), UInt8(n & 0xFF)]
        }
        func derInteger(_ hex: String) -> [UInt8] {
            var bytes = hexBytes(hex)
            while bytes.count > 1 && bytes[0] == 0 { bytes.removeFirst() }
            if let f = bytes.first, f >= 0x80 { bytes.insert(0, at: 0) }
            return [0x02] + derLength(bytes.count) + bytes
        }
        // PKCS#1 RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
        let body = derInteger(modulusHex) + derInteger(exponentHex)
        let der = Data([0x30] + derLength(body.count) + body)

        let attrs: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPublic]
        var err: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(der as CFData, attrs as CFDictionary, &err),
              let out = SecKeyCreateEncryptedData(key, .rsaEncryptionPKCS1, Data(text.utf8) as CFData, &err) as Data?
        else {
            throw RouterError.router("encryption failed: \(err?.takeRetainedValue().localizedDescription ?? "?")")
        }
        return out.map { String(format: "%02x", $0) }.joined()
    }

    static func hexBytes(_ hex: String) -> [UInt8] {
        var h = hex.count % 2 == 1 ? "0" + hex : hex
        var out: [UInt8] = []
        while !h.isEmpty {
            out.append(UInt8(h.prefix(2), radix: 16) ?? 0)
            h = String(h.dropFirst(2))
        }
        return out
    }
}
