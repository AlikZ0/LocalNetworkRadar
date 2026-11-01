import Foundation

struct NetworkDevice: Identifiable, Hashable, Sendable {
    var id: String { ip }
    let ip: String
    var hostname: String? = nil
    var friendlyName: String? = nil
    var openPorts: [Int] = []
    var bonjourServices: [String] = []
    var isTrusted: Bool = false

    var displayName: String { friendlyName ?? hostname ?? "Устройство без имени" }

    var symbol: String {
        let services = Set(bonjourServices)
        if !services.isDisjoint(with: ["_airplay._tcp", "_googlecast._tcp"]) { return "tv" }
        if !services.isDisjoint(with: ["_ipp._tcp", "_printer._tcp"]) { return "printer" }
        if services.contains("_raop._tcp") { return "hifispeaker" }
        if services.contains("_hap._tcp") { return "house" }
        if services.contains("_smb._tcp") || openPorts.contains(445) { return "externaldrive.connected.to.line.below" }
        if openPorts.contains(62078) { return "iphone" }
        return "network"
    }
}

@MainActor
final class TrustStore {
    private let defaults: UserDefaults
    private let key = "LocalNetworkRadar.trustedIPv4.v1"
    private var records: [String: Set<String>]

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        records = defaults.data(forKey: key)
            .flatMap { try? JSONDecoder().decode([String: Set<String>].self, from: $0) } ?? [:]
    }

    // CIDR reduces accidental reuse across different address ranges. It is NOT a
    // network identity: two Wi-Fi networks can have the same CIDR and host IPs.
    // DHCP can also reassign a trusted IP. This is a label, not authentication.
    func isTrusted(ip: String, scope: String) -> Bool {
        records[scope, default: []].contains(ip)
    }

    func setTrusted(_ trusted: Bool, ip: String, scope: String) {
        if trusted { records[scope, default: []].insert(ip) }
        else { records[scope]?.remove(ip) }
        if let data = try? JSONEncoder().encode(records) { defaults.set(data, forKey: key) }
    }
}
