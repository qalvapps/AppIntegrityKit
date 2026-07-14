import CryptoKit
import Foundation
import Testing
@testable import AppIntegrityKit

struct AppIntegrityKitTests {
    @Test func singletonSurfaceExists() {
        #expect(AppIntegrity.shared === AppIntegrity.shared)
        #expect(AppIntegrity.version == "0.1.0-dev")
    }

    @Test func sharedVectorProducesIdenticalCanonicalBytes() throws {
        let vector = try Self.loadVector()
        let evidence = try Base64URL.decode(vector.inputs.entitlementEvidence)
        let configuration = Self.configuration(
            requestedScopes: Set(vector.inputs.requestedScopes)
        )
        let challenge = AppIntegrityChallenge(
            protocolVersion: vector.inputs.protocolVersion,
            challengeID: vector.inputs.challengeID,
            challenge: vector.inputs.challenge,
            purpose: .session,
            expiresAt: .distantFuture
        )

        let result = try SessionClientDataEncoder.makeClientData(
            configuration: configuration,
            challenge: challenge,
            keyID: vector.inputs.keyID,
            entitlementEvidence: evidence
        )

        #expect(String(data: result.encoded, encoding: .utf8) == vector.expected.clientDataUTF8)
        #expect(Base64URL.encode(result.encoded) == vector.expected.clientDataBase64URL)
        #expect(
            Base64URL.encode(Data(SHA256.hash(data: result.encoded)))
                == vector.expected.clientDataSHA256
        )
        #expect(
            result.model.entitlementEvidenceSHA256
                == vector.expected.entitlementEvidenceSHA256
        )
        #expect(result.model.requestedScopes == [
            "tides:forecast",
            "tides:licensed-global"
        ])
    }

    @Test func firstSessionRegistersThenUsesAssertionAndCachesSession() async throws {
        let transport = FakeTransport()
        let appAttest = FakeAppAttestService()
        let store = InMemoryAppIntegrityCredentialStore()
        let client = AppIntegrity()
        try await client.configure(
            Self.configuration(),
            transport: transport,
            appAttestService: appAttest,
            credentialStore: store
        )

        let first = try await client.session(entitlementEvidence: Data("entitlement".utf8))
        let second = try await client.session(entitlementEvidence: Data("entitlement".utf8))

        #expect(first == second)
        #expect(first.token == Base64URL.encode(Data(repeating: 9, count: 32)))
        #expect(await appAttest.generateKeyCount == 1)
        #expect(await appAttest.attestationHashes.count == 1)
        #expect(await appAttest.assertionHashes.count == 1)
        #expect(await transport.registrationRequests.count == 1)
        #expect(await transport.sessionRequests.count == 1)
        #expect(
            await store.keyRecord(for: "goodtides-ios")
                == AppIntegrityKeyRecord(keyID: "key-123", isRegistered: true)
        )
    }

    @Test func pendingKeyIsPersistedBeforeAttestationCompletes() async throws {
        let transport = FakeTransport(registrationFailureCount: 1)
        let appAttest = FakeAppAttestService()
        let store = InMemoryAppIntegrityCredentialStore()
        let client = AppIntegrity()
        try await client.configure(
            Self.configuration(),
            transport: transport,
            appAttestService: appAttest,
            credentialStore: store
        )

        await #expect(throws: AppIntegrityError.transportFailure(
            statusCode: 503,
            code: "temporarily_unavailable"
        )) {
            try await client.session()
        }

        #expect(
            await store.keyRecord(for: "goodtides-ios")
                == AppIntegrityKeyRecord(keyID: "key-123", isRegistered: false)
        )

        _ = try await client.session()
        #expect(await appAttest.generateKeyCount == 1)
        #expect(await appAttest.attestationHashes.count == 2)
    }

    @Test func unsupportedSurfaceFailsClosed() async throws {
        let client = AppIntegrity()
        try await client.configure(
            Self.configuration(),
            transport: FakeTransport(),
            appAttestService: FakeAppAttestService(supported: false),
            credentialStore: InMemoryAppIntegrityCredentialStore()
        )

        await #expect(throws: AppIntegrityError.appAttestNotSupported) {
            try await client.session()
        }
    }

    @Test func insecureRemoteBaseURLIsRejected() async {
        let client = AppIntegrity()
        let configuration = AppIntegrityConfiguration(
            applicationID: "goodtides-ios",
            apiBaseURL: URL(string: "http://example.com")!,
            requestedScopes: ["tides:forecast"]
        )

        await #expect(throws: AppIntegrityError.invalidConfiguration(
            "apiBaseURL must use HTTPS"
        )) {
            try await client.configure(
                configuration,
                transport: FakeTransport(),
                appAttestService: FakeAppAttestService(),
                credentialStore: InMemoryAppIntegrityCredentialStore()
            )
        }
    }

    @Test func oversizedEntitlementEvidenceFailsBeforeNetworking() async throws {
        let transport = FakeTransport()
        let client = AppIntegrity()
        try await client.configure(
            Self.configuration(),
            transport: transport,
            appAttestService: FakeAppAttestService(),
            credentialStore: InMemoryAppIntegrityCredentialStore()
        )

        await #expect(throws: AppIntegrityError.entitlementEvidenceTooLarge) {
            try await client.session(entitlementEvidence: Data(repeating: 0, count: 256 * 1_024 + 1))
        }
        #expect(await transport.challengeRequests.isEmpty)
    }

    private static func configuration(
        requestedScopes: Set<String> = ["tides:forecast", "tides:licensed-global"]
    ) -> AppIntegrityConfiguration {
        AppIntegrityConfiguration(
            applicationID: "goodtides-ios",
            apiBaseURL: URL(string: "https://api.goodtides.example")!,
            requestedScopes: requestedScopes,
            sessionRefreshLeeway: 30,
            keychainService: "test.AppIntegrityKit"
        )
    }

    private static func loadVector() throws -> SessionVector {
        let repositoryRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let url = repositoryRoot
            .appendingPathComponent("Protocol")
            .appendingPathComponent("test-vectors")
            .appendingPathComponent("session-client-data-v1.json")
        return try JSONDecoder().decode(SessionVector.self, from: Data(contentsOf: url))
    }
}

private struct SessionVector: Decodable {
    struct Inputs: Decodable {
        let protocolVersion: Int
        let applicationID: String
        let challengeID: String
        let challenge: String
        let keyID: String
        let requestedScopes: [String]
        let entitlementEvidence: String
    }

    struct Expected: Decodable {
        let entitlementEvidenceSHA256: String
        let clientDataUTF8: String
        let clientDataBase64URL: String
        let clientDataSHA256: String
    }

    let name: String
    let inputs: Inputs
    let expected: Expected
}

private actor FakeAppAttestService: AppAttestServicing {
    let supported: Bool
    private(set) var generateKeyCount = 0
    private(set) var attestationHashes: [Data] = []
    private(set) var assertionHashes: [Data] = []

    init(supported: Bool = true) {
        self.supported = supported
    }

    func isSupported() -> Bool {
        supported
    }

    func generateKey() -> String {
        generateKeyCount += 1
        return "key-123"
    }

    func attestKey(_ keyID: String, clientDataHash: Data) -> Data {
        attestationHashes.append(clientDataHash)
        return Data("attestation".utf8)
    }

    func generateAssertion(_ keyID: String, clientDataHash: Data) -> Data {
        assertionHashes.append(clientDataHash)
        return Data("assertion".utf8)
    }
}

private actor FakeTransport: AppIntegrityTransport {
    private(set) var challengeRequests: [AppIntegrityChallengePurpose] = []
    private(set) var registrationRequests: [AppIntegrityAttestationRequest] = []
    private(set) var sessionRequests: [AppIntegritySessionRequest] = []
    private var registrationFailureCount: Int

    init(registrationFailureCount: Int = 0) {
        self.registrationFailureCount = registrationFailureCount
    }

    func requestChallenge(
        applicationID: String,
        purpose: AppIntegrityChallengePurpose
    ) -> AppIntegrityChallenge {
        challengeRequests.append(purpose)
        return AppIntegrityChallenge(
            protocolVersion: 1,
            challengeID: "\(purpose.rawValue)-challenge",
            challenge: Base64URL.encode(Data((0..<32).map(UInt8.init))),
            purpose: purpose,
            expiresAt: .now.addingTimeInterval(300)
        )
    }

    func registerAttestation(
        _ request: AppIntegrityAttestationRequest
    ) throws -> AppIntegrityAttestationResponse {
        registrationRequests.append(request)
        if registrationFailureCount > 0 {
            registrationFailureCount -= 1
            throw AppIntegrityError.transportFailure(
                statusCode: 503,
                code: "temporarily_unavailable"
            )
        }
        return AppIntegrityAttestationResponse(protocolVersion: 1, registered: true)
    }

    func establishSession(
        _ request: AppIntegritySessionRequest
    ) -> AppIntegritySessionResponse {
        sessionRequests.append(request)
        return AppIntegritySessionResponse(
            protocolVersion: 1,
            sessionToken: Base64URL.encode(Data(repeating: 9, count: 32)),
            expiresAt: .now.addingTimeInterval(1_800),
            scopes: ["tides:forecast", "tides:licensed-global"]
        )
    }
}
