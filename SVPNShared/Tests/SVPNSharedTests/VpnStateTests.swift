import Foundation
@testable import SVPNModels
import Testing

@Suite("VpnState + traffic codable")
struct VpnStateTests {
    @Test
    func `VpnState round-trips through seconds-since-1970 JSON`() throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970

        let state = VpnState(
            stage: .connected,
            profileID: "abc",
            profileName: "HK",
            message: nil,
            startedAt: Date(timeIntervalSince1970: 1_700_000_000),
        )

        let data = try encoder.encode(state)
        let decoded = try decoder.decode(VpnState.self, from: data)
        #expect(decoded == state)
        #expect(decoded.stage.isActive)
    }

    @Test
    func `disconnected stage is not active`() {
        #expect(VpnStage.disconnected.isActive == false)
        #expect(VpnStage.error.isActive == false)
        #expect(VpnStage.connecting.isActive)
    }

    @Test
    func `TrafficSnapshot round-trips`() throws {
        let snap = TrafficSnapshot(
            uploadBytes: 1024,
            downloadBytes: 4096,
            uploadRate: 128,
            downloadRate: 512,
            timestamp: Date(timeIntervalSince1970: 1_700_000_123),
            footprintMB: 27,
        )
        let data = try JSONEncoder().encode(snap)
        let decoded = try JSONDecoder().decode(TrafficSnapshot.self, from: data)
        #expect(decoded == snap)
    }
}
