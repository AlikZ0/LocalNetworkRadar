import Foundation
import Network

enum ProbeOutcome: Sendable { case open, notOpen, denied, cancelled }

// All mutable state, including cancellation and continuation resumption, is
// confined to one serial queue. @unchecked Sendable does not remove that rule.
final class TCPProbe: @unchecked Sendable {
    private let queue: DispatchQueue
    private let context: NetworkContext
    private let ip: String
    private let port: UInt16
    private let timeoutSeconds: TimeInterval
    private var connection: NWConnection?
    private var timer: DispatchWorkItem?
    private var continuation: CheckedContinuation<ProbeOutcome, Never>?
    private var result: ProbeOutcome?

    init(ip: String, port: UInt16, context: NetworkContext,
         timeout: TimeInterval = 0.8, queue: DispatchQueue) {
        self.ip = ip; self.port = port; self.context = context
        timeoutSeconds = timeout; self.queue = queue
    }

    func run() async -> ProbeOutcome {
        await withTaskCancellationHandler(operation: {
            await withCheckedContinuation { continuation in
                queue.async { self.begin(continuation) }
            }
        }, onCancel: { self.queue.async { self.finish(.cancelled) } })
    }

    private func begin(_ continuation: CheckedContinuation<ProbeOutcome, Never>) {
        // A cancelled task may enqueue cancellation before begin().
        if let result { continuation.resume(returning: result); return }
        self.continuation = continuation
        guard let port = NWEndpoint.Port(rawValue: port) else { finish(.notOpen); return }
        // This is a TCP handshake only, including on 443: no TLS, HTTP request,
        // credential exchange, ARP-table access, ICMP, or payload is used.
        let connection = NWConnection(host: NWEndpoint.Host(ip), port: port, using: context.parameters())
        self.connection = connection
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready: self.finish(.open)
            case .waiting:
                if connection.currentPath?.unsatisfiedReason == .localNetworkDenied { self.finish(.denied) }
            case .failed:
                if connection.currentPath?.unsatisfiedReason == .localNetworkDenied { self.finish(.denied) }
                else { self.finish(.notOpen) }
            case .cancelled: self.finish(.cancelled)
            default: break
            }
        }
        let timer = DispatchWorkItem { [weak self] in self?.finish(.notOpen) }
        self.timer = timer
        queue.asyncAfter(deadline: .now() + timeoutSeconds, execute: timer)
        connection.start(queue: queue)
    }

    private func finish(_ value: ProbeOutcome) {
        guard result == nil else { return }
        result = value
        timer?.cancel(); timer = nil
        connection?.stateUpdateHandler = nil
        connection?.cancel(); connection = nil
        let pending = continuation
        continuation = nil
        pending?.resume(returning: value)
    }
}
