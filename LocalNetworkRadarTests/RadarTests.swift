import XCTest
@testable import LocalNetworkRadar

final class RadarTests: XCTestCase {
    func testSlash24UsesRealMaskAndExcludesSelfNetworkBroadcast() throws {
        let subnet = try IPv4Subnet(address: XCTUnwrap(IPv4Subnet.number("192.168.7.42")),
                                    mask: XCTUnwrap(IPv4Subnet.number("255.255.255.0")))
        let hosts = try subnet.targets()
        XCTAssertEqual(subnet.cidr, "192.168.7.0/24")
        XCTAssertEqual(hosts.count, 253)
        XCTAssertEqual(hosts.first, "192.168.7.1")
        XCTAssertEqual(hosts.last, "192.168.7.254")
        XCTAssertFalse(hosts.contains("192.168.7.42"))
        XCTAssertFalse(hosts.contains("192.168.7.0"))
        XCTAssertFalse(hosts.contains("192.168.7.255"))
    }

    func testSlash23CrossesLastOctetBoundary() throws {
        let subnet = try IPv4Subnet(address: XCTUnwrap(IPv4Subnet.number("10.0.3.18")),
                                    mask: XCTUnwrap(IPv4Subnet.number("255.255.254.0")))
        let hosts = try subnet.targets()
        XCTAssertEqual(subnet.cidr, "10.0.2.0/23")
        XCTAssertEqual(hosts.count, 509)
        XCTAssertTrue(hosts.contains("10.0.2.255"))
        XCTAssertTrue(hosts.contains("10.0.3.0"))
    }

    func testLargeNetworkFailsInsteadOfSilentlyClippingToSlash24() throws {
        let subnet = try IPv4Subnet(address: XCTUnwrap(IPv4Subnet.number("10.0.3.18")),
                                    mask: XCTUnwrap(IPv4Subnet.number("255.255.0.0")))
        XCTAssertThrowsError(try subnet.targets()) { error in
            guard let error = error as? ScanError, case .tooLarge(let cidr, let count) = error else {
                return XCTFail("Wrong error")
            }
            XCTAssertEqual(cidr, "10.0.0.0/16")
            XCTAssertEqual(count, 65533)
        }
    }

    func testNoncontiguousMaskIsRejected() {
        XCTAssertThrowsError(try IPv4Subnet(address: 0xC0A80110, mask: 0xFF00FF00))
    }

    func testPointToPointAndSingleAddressNetworks() throws {
        let subnet = try IPv4Subnet(address: 0x0A000000, mask: 0xFFFFFFFE)
        XCTAssertEqual(try subnet.targets(), ["10.0.0.1"])
        let single = try IPv4Subnet(address: 0x0A000001, mask: 0xFFFFFFFF)
        XCTAssertThrowsError(try single.targets())
    }

    @MainActor
    func testTrustPersistsAndIsScopedToCIDR() async throws {
        let suite = "RadarTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let store = TrustStore(defaults: defaults)
        store.setTrusted(true, ip: "192.168.1.7", scope: "192.168.1.0/24")
        let reloaded = TrustStore(defaults: defaults)
        XCTAssertTrue(reloaded.isTrusted(ip: "192.168.1.7", scope: "192.168.1.0/24"))
        XCTAssertFalse(reloaded.isTrusted(ip: "192.168.1.7", scope: "192.168.1.0/23"))
        reloaded.setTrusted(false, ip: "192.168.1.7", scope: "192.168.1.0/24")
        XCTAssertFalse(TrustStore(defaults: defaults).isTrusted(ip: "192.168.1.7", scope: "192.168.1.0/24"))
    }
}
