import SwiftUI

@MainActor
struct ContentView: View {
    @StateObject private var scanner = NetworkScanner()
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        NavigationStack {
            Group {
                if scanner.permissionDenied { permissionView }
                else { deviceList }
            }
            .navigationTitle("Network Radar")
            .navigationBarTitleDisplayMode(.large)
            .navigationDestination(for: String.self) { ip in
                DeviceDetailView(ip: ip, scanner: scanner)
            }
            .safeAreaInset(edge: .bottom) { scanControls }
            .alert("Неизвестные устройства", isPresented: $scanner.showUnknownAlert) {
                Button("Понятно", role: .cancel) { }
            } message: { Text(scanner.unknownAlertMessage) }
        }
        .onChange(of: scenePhase) { _, phase in
            // A system permission alert can cause .inactive. Only stop on real
            // backgrounding. iOS does not allow continuous background LAN scans.
            if phase == .background { scanner.stopScan() }
        }
    }

    private var deviceList: some View {
        List {
            Section {
                VStack(alignment: .leading, spacing: 12) {
                    Label("Устройства рядом", systemImage: "dot.radiowaves.left.and.right")
                        .font(.headline)
                    Text(scanner.status).font(.subheadline).foregroundStyle(.secondary)
                    if !scanner.networkDescription.isEmpty {
                        Text(scanner.networkDescription)
                            .font(.caption.monospaced()).foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }
                    if scanner.isScanning {
                        if scanner.totalHosts > 0, !scanner.isCheckingAccess {
                            ProgressView(value: scanner.progress)
                            Text("Проверено адресов: \(scanner.completedHosts) / \(scanner.totalHosts)")
                                .font(.caption).foregroundStyle(.secondary)
                        } else { ProgressView() }
                    } else if let lastScan = scanner.lastScan {
                        Text("Последний полный поиск: \(lastScan.formatted(date: .omitted, time: .shortened))")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                .padding(.vertical, 6)
            }
            if let error = scanner.errorMessage {
                Section {
                    Label(error, systemImage: "exclamationmark.triangle")
                        .font(.subheadline).foregroundStyle(.orange)
                    Button("Открыть Настройки") { scanner.openSettings() }
                }
            }
            if let warning = scanner.warningMessage {
                Section {
                    Text("Bonjour-поиск мог быть неполным. \(warning)")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            if scanner.devices.isEmpty, !scanner.isScanning {
                Section {
                    ContentUnavailableView(
                        scanner.lastScan == nil ? "Начните поиск" : "Устройства не найдены",
                        systemImage: "network",
                        description: Text("Нажмите «Сканировать». Устройство должно отвечать по TCP или объявлять один из поддерживаемых Bonjour-сервисов.")
                    )
                }
            }
            Section {
                ForEach(scanner.trustedDevices) { device in deviceRow(device) }
            } header: {
                Label("Мои устройства · \(scanner.trustedDevices.count)", systemImage: "checkmark.shield")
                    .foregroundStyle(.green)
            }
            Section {
                ForEach(scanner.unknownDevices) { device in deviceRow(device) }
            } header: {
                Label("Неизвестные · \(scanner.unknownDevices.count)", systemImage: "questionmark.diamond")
                    .foregroundStyle(.orange)
            } footer: {
                Text("«Неизвестное» означает, что вы ещё не добавили IP в доверенные. Приложение не получает список клиентов роутера и может пропустить спящие устройства или устройства без доступных сервисов. Этот iPhone исключён из поиска.")
            }
            Section("О метках доверия") {
                Text("Метки сохраняются по IP и подсети. DHCP может выдать тот же IP другому устройству. Разные Wi-Fi с одинаковой подсетью здесь не различаются. Имя и значок устройства не подтверждают его подлинность.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .listStyle(.insetGrouped)
    }

    private func deviceRow(_ device: NetworkDevice) -> some View {
        NavigationLink(value: device.ip) { DeviceRow(device: device) }
            .swipeActions(edge: .trailing) {
                Button {
                    scanner.setTrusted(ip: device.ip, trusted: !device.isTrusted)
                } label: {
                    Label(device.isTrusted ? "Убрать доверие" : "Это моё",
                          systemImage: device.isTrusted ? "shield.slash" : "checkmark.shield")
                }
                .tint(device.isTrusted ? .orange : .green)
            }
    }

    private var permissionView: some View {
        ScrollView {
            VStack(spacing: 18) {
                Image(systemName: "network.slash").font(.system(size: 54)).foregroundStyle(.orange)
                    .accessibilityHidden(true)
                Text("Разрешите доступ к локальной сети").font(.title2.bold()).multilineTextAlignment(.center)
                Text("iOS запретила локальные сетевые операции. Для поиска ТВ, принтеров и других устройств включите доступ для Local Network Radar в Настройках.")
                    .foregroundStyle(.secondary).multilineTextAlignment(.center)
                Button("Открыть Настройки") { scanner.openSettings() }.buttonStyle(.borderedProminent)
                Text("Если переключателя нет на странице приложения: Настройки → Конфиденциальность и безопасность → Локальная сеть.")
                    .font(.caption).foregroundStyle(.secondary).multilineTextAlignment(.center)
            }
            .padding(28).padding(.top, 35)
        }
    }

    private var scanControls: some View {
        VStack(spacing: 6) {
            Button {
                if scanner.isScanning { scanner.stopScan() } else { scanner.startScan() }
            } label: {
                Label(scanner.isScanning ? "Остановить поиск" : "Сканировать",
                      systemImage: scanner.isScanning ? "stop.circle" : "dot.radiowaves.left.and.right")
                    .font(.headline).frame(maxWidth: .infinity).padding(.vertical, 7)
            }
            .buttonStyle(.borderedProminent)
            .tint(scanner.isScanning ? .orange : .accentColor)
            Text("Поиск работает, пока приложение открыто")
                .font(.caption2).foregroundStyle(.secondary)
        }
        .padding(.horizontal, 20).padding(.vertical, 12)
        .background(.regularMaterial)
    }
}

private struct DeviceRow: View {
    let device: NetworkDevice

    var body: some View {
        HStack(spacing: 13) {
            Image(systemName: device.symbol)
                .font(.title2).frame(width: 42, height: 44)
                .foregroundStyle(device.isTrusted ? .green : .orange)
                .background((device.isTrusted ? Color.green : .orange).opacity(0.10), in: RoundedRectangle(cornerRadius: 12))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 4) {
                Text(device.displayName).font(.subheadline.weight(.semibold)).lineLimit(2)
                Text(device.ip).font(.caption.monospaced()).foregroundStyle(.secondary)
                Label(device.isTrusted ? "Доверенное" : "Неизвестное",
                      systemImage: device.isTrusted ? "checkmark.shield.fill" : "questionmark.circle")
                    .font(.caption2).foregroundStyle(device.isTrusted ? .green : .orange)
            }
        }
        .padding(.vertical, 3)
    }
}

@MainActor
private struct DeviceDetailView: View {
    let ip: String
    @ObservedObject var scanner: NetworkScanner
    private var device: NetworkDevice? { scanner.devices.first { $0.ip == ip } }

    var body: some View {
        Group {
            if let device {
                List {
                    Section {
                        DeviceRow(device: device)
                        LabeledContent("IP-адрес", value: device.ip).textSelection(.enabled)
                        if let hostname = device.hostname {
                            LabeledContent("Hostname", value: hostname).textSelection(.enabled)
                        }
                        Button {
                            scanner.setTrusted(ip: ip, trusted: !device.isTrusted)
                        } label: {
                            Label(device.isTrusted ? "Убрать из доверенных" : "Это моё устройство",
                                  systemImage: device.isTrusted ? "shield.slash" : "checkmark.shield")
                        }
                        .tint(device.isTrusted ? .orange : .green)
                    }
                    Section {
                        if device.openPorts.isEmpty {
                            Text("Открытые порты из проверенного списка не найдены.").foregroundStyle(.secondary)
                        }
                        ForEach(device.openPorts, id: \.self) { port in
                            LabeledContent("TCP \(port)", value: portName(port))
                        }
                    } header: { Text("Открытые TCP-порты") } footer: {
                        Text("Проверены только 80, 443, 22, 445 и 62078. Подтверждается TCP-соединение, содержимое сервисов не проверяется. Таймаут не доказывает, что порт закрыт.")
                    }
                    Section {
                        if device.bonjourServices.isEmpty {
                            Text("Bonjour-сервисы не найдены.").foregroundStyle(.secondary)
                        }
                        ForEach(device.bonjourServices, id: \.self) { type in
                            Text(type).font(.body.monospaced()).textSelection(.enabled)
                        }
                    } header: { Text("Bonjour-сервисы") } footer: {
                        Text("Имя и тип сервиса объявляет само устройство. Объявленный сервис не гарантирует, что его TCP-порт доступен. Значок выбран по косвенным признакам и может быть неточным.")
                    }
                }
            } else {
                ContentUnavailableView("Результат недоступен", systemImage: "network",
                                       description: Text("Вернитесь к списку и дождитесь нового сканирования."))
            }
        }
        .navigationTitle("Устройство").navigationBarTitleDisplayMode(.inline)
    }

    private func portName(_ port: Int) -> String {
        switch port {
        case 80: return "Обычно HTTP"
        case 443: return "Обычно HTTPS"
        case 22: return "Обычно SSH"
        case 445: return "Обычно SMB"
        case 62078: return "Обычно сервис Apple"
        default: return "TCP"
        }
    }
}
