import Foundation
import Combine
import UIKit

private struct HostProbeResult: Sendable {
    let ip: String
    let openPorts: [Int]
    let denied: Bool
}

@MainActor
final class NetworkScanner: ObservableObject {
    @Published private(set) var devices: [NetworkDevice] = []
    @Published private(set) var isScanning = false
    @Published private(set) var isCheckingAccess = false
    @Published private(set) var permissionDenied = false
    @Published private(set) var status = "Подключитесь к Wi-Fi и начните поиск"
    @Published private(set) var networkDescription = ""
    @Published private(set) var errorMessage: String?
    @Published private(set) var warningMessage: String?
    @Published private(set) var completedHosts = 0
    @Published private(set) var totalHosts = 0
    @Published private(set) var lastScan: Date?
    @Published var showUnknownAlert = false
    private(set) var unknownAlertMessage = ""

    // Five well-known TCP ports, max 16 host tasks x 5 probes = 80 connections.
    // This is a bounded reachability check, not a complete port scanner.
    // It makes no guarantee of App Store approval or complete LAN visibility.
    nonisolated static let ports: [UInt16] = [80, 443, 22, 445, 62078]
    private static let hostConcurrency = 16
    private let probeQueue = DispatchQueue(label: "radar.tcp-events")
    private let trustStore: TrustStore
    private var scope: String?
    private var scanTask: Task<Void, Never>?
    private var scanID = UUID()
    private var bonjour: BonjourDiscovery?
    private var previousIPs: [String: Set<String>] = [:]

    init(trustStore: TrustStore? = nil) { self.trustStore = trustStore ?? TrustStore() }

    var trustedDevices: [NetworkDevice] { devices.filter(\.isTrusted) }
    var unknownDevices: [NetworkDevice] { devices.filter { !$0.isTrusted } }
    var progress: Double { totalHosts == 0 ? 0 : Double(completedHosts) / Double(totalHosts) }

    func startScan() {
        guard !isScanning else { return }
        isScanning = true; permissionDenied = false
        devices = []; errorMessage = nil; warningMessage = nil
        networkDescription = ""; scope = nil
        completedHosts = 0; totalHosts = 0; showUnknownAlert = false
        status = "Определяем IPv4-подсеть…"
        scanID = UUID()
        let id = scanID
        scanTask = Task { [weak self] in
            guard let self else { return }
            await self.performScan(id: id)
        }
    }

    func stopScan() {
        guard isScanning else { return }
        status = "Останавливаем поиск…"
        scanTask?.cancel()
        bonjour?.stop()
    }

    func setTrusted(ip: String, trusted: Bool) {
        guard let scope, let index = devices.firstIndex(where: { $0.ip == ip }) else { return }
        trustStore.setTrusted(trusted, ip: ip, scope: scope)
        devices[index].isTrusted = trusted
    }

    func openSettings() {
        guard let url = URL(string: UIApplication.openSettingsURLString) else { return }
        UIApplication.shared.open(url)
    }

    private func performScan(id: UUID) async {
        defer {
            bonjour?.stop(); bonjour = nil
            isScanning = false; isCheckingAccess = false; scanTask = nil
        }
        do {
            let context = try await NetworkContext.current()
            let targets = try context.subnet.targets()
            scope = context.subnet.cidr
            networkDescription = "\(context.subnet.cidr) · iPhone \(context.subnet.localIP) · \(context.interface.name)"
            totalHosts = targets.count
            status = "Подтвердите доступ к локальной сети…"
            isCheckingAccess = true
            let access = await LocalNetworkAccess().request(context: context)
            isCheckingAccess = false
            try Task.checkCancellation()
            switch access {
            case .allowed: break
            case .denied: denyAccess(); return
            case .cancelled: throw CancellationError()
            case .unavailable(let message): throw ScanError.accessNotConfirmed(message)
            }
            guard context.isCurrent else { throw ScanError.networkChanged }
            status = "Ищем устройства и Bonjour-сервисы…"
            let started = Date()
            let discovery = BonjourDiscovery(context: context, onIdentity: { [weak self] identity in
                guard let self, self.scanID == id, self.isScanning, !self.permissionDenied else { return }
                self.merge(identity)
            }, onDenied: { [weak self] in
                guard let self, self.scanID == id, self.isScanning else { return }
                self.denyAccess(); self.scanTask?.cancel()
            }, onWarning: { [weak self] message in
                guard let self, self.scanID == id, self.isScanning else { return }
                self.warningMessage = message
            })
            bonjour = discovery
            discovery.start()
            try await scanHosts(targets, context: context)
            try Task.checkCancellation()
            // Keep Bonjour alive for at least six seconds on very small LANs.
            let remaining = 6 - Date().timeIntervalSince(started)
            if remaining > 0 {
                status = "Завершаем поиск Bonjour…"
                try await Task.sleep(nanoseconds: UInt64(remaining * 1_000_000_000))
            }
            guard context.isCurrent else { throw ScanError.networkChanged }
            try Task.checkCancellation()
            discovery.stop()
            lastScan = Date()
            status = "Поиск завершён · найдено: \(devices.count)"
            announceUnknown(scope: context.subnet.cidr)
        } catch is CancellationError {
            if !permissionDenied { status = "Поиск остановлен · результаты неполные" }
        } catch {
            if let scanError = error as? ScanError, case .networkChanged = scanError {
                devices = []; scope = nil; networkDescription = ""
            }
            errorMessage = error.localizedDescription
            status = "Не удалось завершить поиск"
        }
    }

    private func scanHosts(_ targets: [String], context: NetworkContext) async throws {
        let queue = probeQueue
        try await withThrowingTaskGroup(of: HostProbeResult.self) { group in
            var nextIndex = 0
            for _ in 0..<min(Self.hostConcurrency, targets.count) {
                let ip = targets[nextIndex]; nextIndex += 1
                group.addTask { await Self.probeHost(ip, context: context, queue: queue) }
            }
            while let result = try await group.next() {
                try Task.checkCancellation()
                if result.denied { denyAccess(); group.cancelAll(); throw CancellationError() }
                if completedHosts % 12 == 0, !context.isCurrent { throw ScanError.networkChanged }
                completedHosts += 1
                if !result.openPorts.isEmpty { merge(result) }
                if nextIndex < targets.count {
                    let ip = targets[nextIndex]; nextIndex += 1
                    group.addTask { await Self.probeHost(ip, context: context, queue: queue) }
                }
            }
        }
    }

    nonisolated private static func probeHost(_ ip: String, context: NetworkContext,
                                             queue: DispatchQueue) async -> HostProbeResult {
        await withTaskGroup(of: (UInt16, ProbeOutcome).self) { group in
            for port in ports {
                group.addTask {
                    guard !Task.isCancelled else { return (port, .cancelled) }
                    let result = await TCPProbe(ip: ip, port: port, context: context, queue: queue).run()
                    return (port, result)
                }
            }
            var open: [Int] = []
            var denied = false
            for await (port, result) in group {
                switch result {
                case .open: open.append(Int(port))
                case .denied: denied = true; group.cancelAll()
                case .notOpen, .cancelled: break
                }
            }
            return HostProbeResult(ip: ip, openPorts: open.sorted(), denied: denied)
        }
    }

    private func device(ip: String) -> NetworkDevice {
        devices.first { $0.ip == ip } ?? NetworkDevice(
            ip: ip, isTrusted: scope.map { trustStore.isTrusted(ip: ip, scope: $0) } ?? false)
    }

    private func merge(_ result: HostProbeResult) {
        var updated = device(ip: result.ip)
        updated.openPorts = Array(Set(updated.openPorts + result.openPorts)).sorted()
        upsert(updated)
    }

    private func merge(_ identity: BonjourIdentity) {
        var updated = device(ip: identity.ip)
        if !identity.hostname.isEmpty { updated.hostname = identity.hostname }
        if updated.friendlyName == nil { updated.friendlyName = identity.friendlyName }
        updated.bonjourServices = Array(Set(updated.bonjourServices + [identity.serviceType])).sorted()
        upsert(updated)
    }

    private func upsert(_ device: NetworkDevice) {
        if let index = devices.firstIndex(where: { $0.ip == device.ip }) { devices[index] = device }
        else { devices.append(device) }
        devices.sort { (IPv4Subnet.number($0.ip) ?? 0) < (IPv4Subnet.number($1.ip) ?? 0) }
    }

    private func denyAccess() {
        permissionDenied = true
        status = "Нет доступа к локальной сети"
        devices = []
    }

    private func announceUnknown(scope: String) {
        let old = previousIPs[scope, default: []]
        let newUnknown = unknownDevices.filter { !old.contains($0.ip) }
        previousIPs[scope] = Set(devices.map(\.ip))
        guard !newUnknown.isEmpty else { return }
        let sample = newUnknown.prefix(5).map(\.ip).joined(separator: ", ")
        unknownAlertMessage = "Новые адреса без метки доверия: \(newUnknown.count).\n\(sample)\n\nПроверьте, какие устройства вам принадлежат. Метка «Неизвестное» сама по себе не означает угрозу."
        showUnknownAlert = true
    }
}
