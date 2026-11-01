import Foundation
import Network
import UIKit

enum AccessOutcome: Sendable { case allowed, denied, cancelled, unavailable(String) }

@MainActor
final class LocalNetworkAccess {
    static let serviceType = "_lnradar._tcp"
    private var browser: NWBrowser?
    private var listener: NWListener?
    private var continuation: CheckedContinuation<AccessOutcome, Never>?
    private var result: AccessOutcome?
    private var timeoutTask: Task<Void, Never>?
    private var denialTask: Task<Void, Never>?
    private var foregroundObserver: NSObjectProtocol?
    private var policyDenied = false
    private let serviceName = UUID().uuidString

    // There is no general API to read the Local Network authorization status.
    // A .ready browser is not proof of permission. A short-lived listener and
    // browser confirm that our own declared service is actually discoverable.
    // A timeout is inconclusive; only a policy error is treated as a denial.
    func request(context: NetworkContext) async -> AccessOutcome {
        await withTaskCancellationHandler(operation: {
            await withCheckedContinuation { continuation in
                if let result { continuation.resume(returning: result); return }
                self.continuation = continuation
                if Task.isCancelled { finish(.cancelled); return }
                begin(context: context)
            }
        }, onCancel: { Task { @MainActor in self.finish(.cancelled) } })
    }

    private func begin(context: NetworkContext) {
        do {
            let listener = try NWListener(using: context.parameters())
            listener.service = NWListener.Service(name: serviceName, type: Self.serviceType)
            listener.newConnectionHandler = { connection in connection.cancel() }
            listener.stateUpdateHandler = { [weak self] state in
                Task { @MainActor in
                    guard let self else { return }
                    if case .failed(let error) = state {
                        if BonjourDiscovery.isDenied(error) { self.noteDenied() }
                        else { self.finish(.unavailable("Не удалось проверить доступ: \(error.localizedDescription)")) }
                    }
                }
            }
            self.listener = listener
            let browser = NWBrowser(for: .bonjour(type: Self.serviceType, domain: "local."), using: context.parameters())
            browser.stateUpdateHandler = { [weak self] state in
                Task { @MainActor in
                    guard let self, self.result == nil else { return }
                    switch state {
                    case .ready:
                        self.policyDenied = false
                        self.denialTask?.cancel()
                    case .waiting(let error), .failed(let error):
                        if BonjourDiscovery.isDenied(error) { self.noteDenied() }
                        else if case .failed = state {
                            self.finish(.unavailable("Не удалось проверить Bonjour: \(error.localizedDescription)"))
                        }
                    default: break
                    }
                }
            }
            browser.browseResultsChangedHandler = { [weak self] results, _ in
                Task { @MainActor in
                    guard let self, self.result == nil else { return }
                    if results.contains(where: { result in
                        if case .service(let name, _, _, _) = result.endpoint { return name == self.serviceName }
                        return false
                    }) { self.finish(.allowed) }
                }
            }
            self.browser = browser
            foregroundObserver = NotificationCenter.default.addObserver(
                forName: UIApplication.didBecomeActiveNotification, object: nil, queue: .main
            ) { [weak self] _ in Task { @MainActor in self?.evaluateDenial() } }
            listener.start(queue: .main)
            browser.start(queue: .main)
            timeoutTask = Task { [weak self] in
                var activeSeconds = 0.0
                while !Task.isCancelled, activeSeconds < 30 {
                    do { try await Task.sleep(nanoseconds: 500_000_000) } catch { return }
                    // Do not consume the timeout while the system alert has
                    // temporarily made the application inactive.
                    if UIApplication.shared.applicationState == .active { activeSeconds += 0.5 }
                }
                guard !Task.isCancelled else { return }
                self?.finish(.unavailable("Доступ к локальной сети не удалось подтвердить. Проверьте Wi-Fi и разрешение в Настройках, затем повторите попытку. Таймаут сам по себе не означает отказ в доступе."))
            }
        } catch { finish(.unavailable(error.localizedDescription)) }
    }

    private func noteDenied() { policyDenied = true; evaluateDenial() }

    private func evaluateDenial() {
        guard result == nil, policyDenied else { return }
        denialTask?.cancel()
        denialTask = Task { [weak self] in
            do { try await Task.sleep(nanoseconds: 750_000_000) } catch { return }
            guard let self, self.policyDenied, UIApplication.shared.applicationState == .active else { return }
            self.finish(.denied)
        }
    }

    private func finish(_ value: AccessOutcome) {
        guard result == nil else { return }
        result = value
        timeoutTask?.cancel(); timeoutTask = nil
        denialTask?.cancel(); denialTask = nil
        if let foregroundObserver { NotificationCenter.default.removeObserver(foregroundObserver) }
        foregroundObserver = nil
        browser?.stateUpdateHandler = nil; browser?.browseResultsChangedHandler = nil
        browser?.cancel(); browser = nil
        listener?.stateUpdateHandler = nil; listener?.newConnectionHandler = nil
        listener?.cancel(); listener = nil
        let pending = continuation
        continuation = nil
        pending?.resume(returning: value)
    }
}
