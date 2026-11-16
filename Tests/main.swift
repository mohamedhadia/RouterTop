// Unit checks for RouterClient. Run: ./scripts/test.sh
import Foundation

var failures = 0
func check(_ ok: Bool, _ msg: String) { print(ok ? "✓ \(msg)" : "✗ \(msg)"); if !ok { failures += 1 } }

// 1. RSA: encrypt with our code, decrypt with OpenSSL (key passed in by test.sh)
let args = CommandLine.arguments
if args.count >= 3 {
    let hex = try RouterClient.rsaEncrypt("aGVsbG8xMjM=", modulusHex: args[1], exponentHex: "010001")
    try Data(RouterClient.hexBytes(hex)).write(to: URL(fileURLWithPath: args[2]))
    check(hex.count == args[1].count, "ciphertext length matches key size (\(hex.count / 2) bytes)")
}

// 2. Parser with the Rx/Tx format from an Archer VR600
let sample = """
[1,0,0,0,0,0]0
hostType=2.4g
hostName=iPhone
ipAddress=3232235879
macAddress=A2:12:92:44:62:79
totalBytesRx=0
totalBytesTx=12595058
[2,0,0,0,0,0]0
hostName=--
ipAddress=3232235884
macAddress=BE:46:08:A2:A6:D2
totalBytes=50839
[error]0
"""
let rows = try RouterClient.parse(sample).map(RouterClient.sample)
check(rows.count == 2, "parses 2 devices")
check(rows[0].ip == "192.168.1.103" && rows[0].total == 12595058 && rows[0].name == "iPhone", "Rx+Tx device")
check(rows[1].total == 50839 && rows[1].name == "BE:46:08:A2:A6:D2", "totalBytes device, unnamed → MAC")
do { _ = try RouterClient.parse("[error]71233\n"); check(false, "router error raised") }
catch { check(true, "router error raised") }
check(RouterClient.match(#"userSetting=(\d+)"#, in: "var userSetting=2;") == "2", "email-login detection")

exit(failures == 0 ? 0 : 1)
