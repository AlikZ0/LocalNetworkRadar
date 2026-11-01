import Foundation
import Network
import dnssd
import Darwin

struct BonjourIdentity: Sendable {
    let ip: String
    let hostname: String
    let friendlyName: String
    let serviceType: String
}

private struct ServiceKey: Hashable, Sendable {
    let name: String
    let type: String
    let domain: String
}

private struct Resolution: Sendable {
    let key: ServiceKey
    let hostname: String
    let addresses: [UInt32]
    let denied: Bool
}

@MainActor
final class BonjourDiscovery {
    static let serviceTypes = [
        "_http._tcp", "_https._tcp", "_ssh._tcp", "_airplay._tcp", "_raop._tcp",
        "_hap._tcp", "_ipp._tcp", "_printer._tcp", "_smb._tcp", "_googlecast._tcp"
    ]

    private let context: NetworkContext
    private let onIdentity: (BonjourIdentity) -> Void
    private let onDenied: () -> Void
    private let onWarning: (String) -> Void
    private let queue = DispatchQueue(label: "radar.bonjour-resolve")
    private var browsers: [NWBrowser] = []
    private var resolvers: [ServiceKey: BonjourResolver] = [:]
    private var pending: [ServiceKey] = []
    private var seen: Set<ServiceKey> = []
    private var active = false

    init(context: NetworkContext, onIdentity: @escaping (BonjourIdentity) -> Void,
         onDenied: @escaping () -> Void, onWarning: @escaping (String) -> Void) {
        self.context = context; self.onIdentity = onIdentity
        self.onDenied = onDenied; self.onWarning = onWarning
    }

    func start() {
        guard !active else { return }
        active = true
        // Fixed, declared types use the system Bonjour implementation. No raw
        // multicast, wildcard service enumeration, or multicast entitlement.
        for type in Self.serviceTypes {
            let browser = NWBrowser(for: .bonjour(type: type, domain: "local."), using: context.parameters())
            browser.stateUpdateHandler = { [weak self] state in
                Task { @MainActor in
                    guard let self, self.active else { return }
                    switch state {
                    case .waiting(let error), .failed(let error):
                        if Self.isDenied(error) { self.onDenied() }
                        else { self.onWarning("Bonjour \(type): \(error.localizedDescription)") }
                    default: break
                    }
                }
            }
            browser.browseResultsChangedHandler = { [weak self] results, _ in
                Task { @MainActor in self?.consume(results) }
            }
            browsers.append(browser)
            browser.start(queue: .main)
        }
    }

    func stop() {
        active = false
        for browser in browsers {
            browser.stateUpdateHandler = nil; browser.browseResultsChangedHandler = nil
            browser.cancel()
        }
        browsers.removeAll()
        for resolver in resolvers.values { resolver.cancel() }
        resolvers.removeAll(); pending.removeAll(); seen.removeAll()
    }

    private func consume(_ results: Set<NWBrowser.Result>) {
        guard active else { return }
        for result in results {
            guard result.interfaces.contains(where: { $0.index == context.interface.index }),
                  case .service(let name, let type, let domain, _) = result.endpoint else { continue }
            let key = ServiceKey(name: name, type: type, domain: domain)
            if seen.insert(key).inserted { pending.append(key) }
        }
        fillResolverSlots()
    }

    private func fillResolverSlots() {
        guard active else { return }
        while resolvers.count < 8, !pending.isEmpty {
            let key = pending.removeFirst()
            let resolver = BonjourResolver(key: key, interfaceIndex: UInt32(context.interface.index), queue: queue) { [weak self] resolution in
                Task { @MainActor in self?.resolved(resolution) }
            }
            resolvers[key] = resolver
            resolver.start()
        }
    }

    private func resolved(_ resolution: Resolution) {
        guard active, resolvers.removeValue(forKey: resolution.key) != nil else { return }
        if resolution.denied { onDenied(); return }
        var type = resolution.key.type
        if type.hasSuffix(".") { type.removeLast() }
        var hostname = resolution.hostname
        if hostname.hasSuffix(".") { hostname.removeLast() }
        for address in resolution.addresses where context.subnet.contains(address) && address != context.subnet.address {
            // A service can identify a host even if all five probed ports are
            // closed. An advertised SRV port is NOT reported as an open port.
            onIdentity(BonjourIdentity(ip: IPv4Subnet.string(address), hostname: hostname,
                                       friendlyName: resolution.key.name, serviceType: type))
        }
        fillResolverSlots()
    }

    nonisolated static func isDenied(_ error: NWError) -> Bool {
        if case .dns(let code) = error { return code == -65570 } // kDNSServiceErr_PolicyDenied
        return false
    }
}

// NWBrowser returns a service endpoint, not its IP or host name. Resolve the SRV
// record, then its IPv4 addresses with dnssd. Apple's TN3151 recommends dnssd
// when service resolution is needed without opening a connection to that service.
private final class BonjourResolver: @unchecked Sendable {
    private let key: ServiceKey
    private let interfaceIndex: UInt32
    private let queue: DispatchQueue
    private let completion: @Sendable (Resolution) -> Void
    private var srvRef: DNSServiceRef?
    private var addressRef: DNSServiceRef?
    private var timer: DispatchWorkItem?
    private var hostname = ""
    private var addresses: Set<UInt32> = []
    private var finished = false

    init(key: ServiceKey, interfaceIndex: UInt32, queue: DispatchQueue,
         completion: @escaping @Sendable (Resolution) -> Void) {
        self.key = key; self.interfaceIndex = interfaceIndex
        self.queue = queue; self.completion = completion
    }

    func start() { queue.async { self.begin() } }
    func cancel() { queue.async { self.finish() } }

    private func begin() {
        guard !finished else { return }
        let opaque = Unmanaged.passUnretained(self).toOpaque()
        let error = DNSServiceResolve(&srvRef, 0, interfaceIndex, key.name, key.type, key.domain,
            { _, _, _, error, _, host, _, _, _, opaque in
                guard let opaque else { return }
                let owner = Unmanaged<BonjourResolver>.fromOpaque(opaque).takeUnretainedValue()
                let hostname = host.map { String(cString: $0) } ?? ""
                // Copy C data and leave the C callback before deallocating a ref.
                owner.queue.async { owner.didResolveSRV(hostname: hostname, error: error) }
            }, opaque)
        guard error == kDNSServiceErr_NoError, let srvRef else { finish(denied: error == -65570); return }
        let dispatchError = DNSServiceSetDispatchQueue(srvRef, queue)
        guard dispatchError == kDNSServiceErr_NoError else { finish(denied: dispatchError == -65570); return }
        let timer = DispatchWorkItem { [weak self] in self?.finish() }
        self.timer = timer
        queue.asyncAfter(deadline: .now() + 3, execute: timer)
    }

    private func didResolveSRV(hostname: String, error: DNSServiceErrorType) {
        guard !finished, addressRef == nil else { return }
        guard error == kDNSServiceErr_NoError, !hostname.isEmpty else { finish(denied: error == -65570); return }
        if let srvRef { DNSServiceRefDeallocate(srvRef); self.srvRef = nil }
        self.hostname = hostname
        let opaque = Unmanaged.passUnretained(self).toOpaque()
        let error = DNSServiceGetAddrInfo(&addressRef, 0, interfaceIndex,
            DNSServiceProtocol(kDNSServiceProtocol_IPv4), hostname,
            { _, flags, _, error, _, address, _, opaque in
                guard let opaque else { return }
                let owner = Unmanaged<BonjourResolver>.fromOpaque(opaque).takeUnretainedValue()
                var value: UInt32?
                if let address, address.pointee.sa_family == sa_family_t(AF_INET) {
                    let ip = UnsafeRawPointer(address).assumingMemoryBound(to: sockaddr_in.self).pointee
                    value = UInt32(bigEndian: ip.sin_addr.s_addr)
                }
                let copiedValue = value
                owner.queue.async { owner.didResolveAddress(copiedValue, flags: flags, error: error) }
            }, opaque)
        guard error == kDNSServiceErr_NoError, let addressRef else { finish(denied: error == -65570); return }
        let dispatchError = DNSServiceSetDispatchQueue(addressRef, queue)
        if dispatchError != kDNSServiceErr_NoError { finish(denied: dispatchError == -65570) }
    }

    private func didResolveAddress(_ address: UInt32?, flags: DNSServiceFlags, error: DNSServiceErrorType) {
        guard !finished else { return }
        guard error == kDNSServiceErr_NoError else { finish(denied: error == -65570); return }
        if let address, flags & DNSServiceFlags(kDNSServiceFlagsAdd) != 0 { addresses.insert(address) }
        if !addresses.isEmpty, flags & DNSServiceFlags(kDNSServiceFlagsMoreComing) == 0 { finish() }
    }

    private func finish(denied: Bool = false) {
        guard !finished else { return }
        finished = true
        timer?.cancel(); timer = nil
        if let srvRef { DNSServiceRefDeallocate(srvRef); self.srvRef = nil }
        if let addressRef { DNSServiceRefDeallocate(addressRef); self.addressRef = nil }
        completion(Resolution(key: key, hostname: hostname, addresses: addresses.sorted(), denied: denied))
    }
}
