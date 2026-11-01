import Foundation
import Network
import Darwin

enum ScanError: LocalizedError {
    case noInterface
    case invalidMask
    case tooLarge(String, Int)
    case noPeers
    case networkChanged
    case accessNotConfirmed(String)

    var errorDescription: String? {
        switch self {
        case .noInterface:
            return "Не найден IPv4-интерфейс Wi-Fi или Ethernet. Подключитесь к локальной сети и повторите сканирование. IPv6-only сети пока не поддерживаются."
        case .invalidMask:
            return "Не удалось определить корректную маску IPv4-подсети."
        case .tooLarge(let cidr, let count):
            return "В подсети \(cidr) доступно \(count) адресов. MVP ограничен 1024 адресами за запуск и не подменяет реальную маску на /24. Bonjour-поиск для такой сети также не запускается."
        case .noPeers:
            return "Эта IPv4-подсеть не содержит других адресов для проверки."
        case .networkChanged:
            return "Сеть или IP-адрес iPhone изменились. Результаты сброшены. Запустите сканирование снова."
        case .accessNotConfirmed(let message): return message
        }
    }
}

struct IPv4Subnet: Equatable, Sendable {
    let address: UInt32
    let mask: UInt32

    init(address: UInt32, mask: UInt32) throws {
        let inverse = ~mask
        guard mask != 0, inverse & (inverse &+ 1) == 0 else { throw ScanError.invalidMask }
        self.address = address
        self.mask = mask
    }

    var prefixLength: Int { mask.nonzeroBitCount }
    var network: UInt32 { address & mask }
    var broadcast: UInt32 { network | ~mask }
    var cidr: String { "\(Self.string(network))/\(prefixLength)" }
    var localIP: String { Self.string(address) }

    func contains(_ value: UInt32) -> Bool { value & mask == network }

    func targets(limit: Int = 1024) throws -> [String] {
        // /31 is a point-to-point network: both addresses are valid hosts.
        let first = prefixLength < 31 ? UInt64(network) + 1 : UInt64(network)
        let last = prefixLength < 31 ? UInt64(broadcast) - 1 : UInt64(broadcast)
        let count = Int(last - first + 1) - (UInt64(address) >= first && UInt64(address) <= last ? 1 : 0)
        guard count > 0 else { throw ScanError.noPeers }
        guard count <= limit else { throw ScanError.tooLarge(cidr, count) }
        return (first...last).compactMap { $0 == UInt64(address) ? nil : Self.string(UInt32($0)) }
    }

    static func number(_ string: String) -> UInt32? {
        var value = in_addr()
        guard string.withCString({ inet_pton(AF_INET, $0, &value) }) == 1 else { return nil }
        return UInt32(bigEndian: value.s_addr)
    }

    static func string(_ value: UInt32) -> String {
        "\((value >> 24) & 255).\((value >> 16) & 255).\((value >> 8) & 255).\(value & 255)"
    }

    static func read(interfaceName: String) -> IPv4Subnet? {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0 else { return nil }
        defer { if let head { freeifaddrs(head) } }
        var cursor = head
        while let node = cursor {
            defer { cursor = node.pointee.ifa_next }
            let item = node.pointee
            guard String(cString: item.ifa_name) == interfaceName,
                  item.ifa_flags & UInt32(IFF_UP) != 0,
                  item.ifa_flags & UInt32(IFF_LOOPBACK) == 0,
                  let address = item.ifa_addr, let netmask = item.ifa_netmask,
                  address.pointee.sa_family == sa_family_t(AF_INET),
                  netmask.pointee.sa_family == sa_family_t(AF_INET) else { continue }
            let ip = UnsafeRawPointer(address).assumingMemoryBound(to: sockaddr_in.self).pointee
            let mask = UnsafeRawPointer(netmask).assumingMemoryBound(to: sockaddr_in.self).pointee
            return try? IPv4Subnet(address: UInt32(bigEndian: ip.sin_addr.s_addr),
                                   mask: UInt32(bigEndian: mask.sin_addr.s_addr))
        }
        return nil
    }
}

struct NetworkContext: @unchecked Sendable {
    let interface: NWInterface
    let subnet: IPv4Subnet

    var isCurrent: Bool { IPv4Subnet.read(interfaceName: interface.name) == subnet }

    func parameters() -> NWParameters {
        let parameters = NWParameters.tcp
        parameters.requiredInterface = interface
        parameters.prohibitedInterfaceTypes = [.cellular]
        parameters.includePeerToPeer = false
        return parameters
    }

    static func current() async throws -> NetworkContext {
        let interfaces = await InterfaceSnapshot().read()
        try Task.checkCancellation()
        // Never assume that en0 is Wi-Fi. Use the names and types provided by
        // Network.framework, then read the address and mask with getifaddrs.
        let candidates = interfaces.filter { $0.type == .wifi || $0.type == .wiredEthernet }
            .sorted { ($0.type == .wifi ? 0 : 1, $0.index) < ($1.type == .wifi ? 0 : 1, $1.index) }
        for interface in candidates {
            if let subnet = IPv4Subnet.read(interfaceName: interface.name) {
                return NetworkContext(interface: interface, subnet: subnet)
            }
        }
        throw ScanError.noInterface
    }
}

private final class InterfaceSnapshot: @unchecked Sendable {
    private let queue = DispatchQueue(label: "radar.interface-snapshot")
    private let monitor = NWPathMonitor()
    private var continuation: CheckedContinuation<[NWInterface], Never>?
    private var result: [NWInterface]?
    private var timeout: DispatchWorkItem?

    func read() async -> [NWInterface] {
        await withTaskCancellationHandler(operation: {
            await withCheckedContinuation { continuation in
                queue.async {
                    if let result = self.result { continuation.resume(returning: result); return }
                    self.continuation = continuation
                    self.monitor.pathUpdateHandler = { [weak self] path in self?.finish(path.availableInterfaces) }
                    let timeout = DispatchWorkItem { [weak self] in self?.finish([]) }
                    self.timeout = timeout
                    self.queue.asyncAfter(deadline: .now() + 3, execute: timeout)
                    self.monitor.start(queue: self.queue)
                }
            }
        }, onCancel: { self.queue.async { self.finish([]) } })
    }

    private func finish(_ value: [NWInterface]) {
        guard result == nil else { return }
        result = value
        timeout?.cancel(); timeout = nil
        monitor.pathUpdateHandler = nil
        monitor.cancel()
        let pending = continuation
        continuation = nil
        pending?.resume(returning: value)
    }
}
