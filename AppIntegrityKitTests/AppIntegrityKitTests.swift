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

    @Test func concurrentEquivalentSessionsShareOneRegistrationAndAssertion() async throws {
        let transport = FakeTransport(challengeDelay: .milliseconds(25))
        let appAttest = FakeAppAttestService(operationDelay: .milliseconds(25))
        let store = InMemoryAppIntegrityCredentialStore()
        let client = AppIntegrity()
        try await client.configure(
            Self.configuration(),
            transport: transport,
            appAttestService: appAttest,
            credentialStore: store
        )

        let sessions = try await withThrowingTaskGroup(of: AppIntegritySession.self) { group in
            for _ in 0..<8 {
                group.addTask {
                    try await client.session(entitlementEvidence: Data("same-evidence".utf8))
                }
            }
            var sessions: [AppIntegritySession] = []
            for try await session in group {
                sessions.append(session)
            }
            return sessions
        }

        #expect(sessions.count == 8)
        #expect(Set(sessions.map(\.token)).count == 1)
        #expect(await appAttest.generateKeyCount == 1)
        #expect(await appAttest.attestationHashes.count == 1)
        #expect(await appAttest.assertionHashes.count == 1)
        #expect(await transport.registrationRequests.count == 1)
        #expect(await transport.sessionRequests.count == 1)
    }

    @Test func concurrentForceRefreshesShareOneNewAssertion() async throws {
        let transport = FakeTransport(challengeDelay: .milliseconds(25))
        let appAttest = FakeAppAttestService(operationDelay: .milliseconds(25))
        let client = AppIntegrity()
        try await client.configure(
            Self.configuration(),
            transport: transport,
            appAttestService: appAttest,
            credentialStore: InMemoryAppIntegrityCredentialStore()
        )
        _ = try await client.session()

        try await withThrowingTaskGroup(of: Void.self) { group in
            for _ in 0..<8 {
                group.addTask {
                    _ = try await client.session(forceRefresh: true)
                }
            }
            try await group.waitForAll()
        }

        #expect(await appAttest.generateKeyCount == 1)
        #expect(await appAttest.attestationHashes.count == 1)
        #expect(await appAttest.assertionHashes.count == 2)
        #expect(await transport.registrationRequests.count == 1)
        #expect(await transport.sessionRequests.count == 2)
    }

    @Test func differentConcurrentSessionRequestsRunInSequence() async throws {
        let transport = FakeTransport(challengeDelay: .milliseconds(25))
        let appAttest = FakeAppAttestService(operationDelay: .milliseconds(25))
        let client = AppIntegrity()
        try await client.configure(
            Self.configuration(),
            transport: transport,
            appAttestService: appAttest,
            credentialStore: InMemoryAppIntegrityCredentialStore()
        )

        async let first = client.session(entitlementEvidence: Data("first".utf8))
        try await Task.sleep(for: .milliseconds(10))
        async let refreshed = client.session(
            entitlementEvidence: Data("second".utf8),
            forceRefresh: true
        )
        _ = try await (first, refreshed)

        #expect(await appAttest.generateKeyCount == 1)
        #expect(await appAttest.attestationHashes.count == 1)
        #expect(await appAttest.assertionHashes.count == 2)
        #expect(await transport.registrationRequests.count == 1)
        #expect(await transport.sessionRequests.count == 2)
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

    @Test func rejectedPendingAttestationKeyIsReplacedOnce() async throws {
        let transport = FakeTransport()
        let appAttest = FakeAppAttestService(
            attestationFailures: [.appAttestKeyRejected]
        )
        let store = InMemoryAppIntegrityCredentialStore()
        let client = AppIntegrity()
        try await client.configure(
            Self.configuration(),
            transport: transport,
            appAttestService: appAttest,
            credentialStore: store
        )

        _ = try await client.session()

        #expect(await appAttest.generateKeyCount == 2)
        #expect(await appAttest.attestationKeyIDs == ["key-123", "key-2"])
        #expect(await appAttest.assertionKeyIDs == ["key-2"])
        #expect(await transport.challengeRequests == [
            .attestation,
            .attestation,
            .session,
        ])
        #expect(await transport.registrationRequests.map(\.keyID) == ["key-2"])
        #expect(
            await store.keyRecord(for: "goodtides-ios")
                == AppIntegrityKeyRecord(keyID: "key-2", isRegistered: true)
        )
    }

    @Test func serverUnavailableRetainsPendingAttestationKey() async throws {
        let transport = FakeTransport()
        let appAttest = FakeAppAttestService(
            attestationFailures: [.appAttestServerUnavailable]
        )
        let store = InMemoryAppIntegrityCredentialStore()
        let client = AppIntegrity()
        try await client.configure(
            Self.configuration(),
            transport: transport,
            appAttestService: appAttest,
            credentialStore: store
        )

        await #expect(throws: AppIntegrityError.appAttestServerUnavailable) {
            try await client.session()
        }
        #expect(
            await store.keyRecord(for: "goodtides-ios")
                == AppIntegrityKeyRecord(keyID: "key-123", isRegistered: false)
        )

        _ = try await client.session()
        #expect(await appAttest.generateKeyCount == 1)
        #expect(await appAttest.attestationKeyIDs == ["key-123", "key-123"])
    }

    @Test func rejectedAttestationReplacementIsBounded() async throws {
        let transport = FakeTransport()
        let appAttest = FakeAppAttestService(
            attestationFailures: [
                .appAttestKeyRejected,
                .appAttestKeyRejected,
            ]
        )
        let store = InMemoryAppIntegrityCredentialStore()
        let client = AppIntegrity()
        try await client.configure(
            Self.configuration(),
            transport: transport,
            appAttestService: appAttest,
            credentialStore: store
        )

        await #expect(throws: AppIntegrityError.appAttestKeyRejected) {
            try await client.session()
        }

        #expect(await appAttest.generateKeyCount == 2)
        #expect(await appAttest.attestationKeyIDs == ["key-123", "key-2"])
        #expect(await transport.registrationRequests.isEmpty)
        #expect(await store.keyRecord(for: "goodtides-ios") == nil)
    }

    @Test func rejectedAssertionKeyRestartsRegistrationOnce() async throws {
        let transport = FakeTransport()
        let appAttest = FakeAppAttestService(
            assertionFailures: [.appAttestKeyRejected]
        )
        let store = InMemoryAppIntegrityCredentialStore()
        let client = AppIntegrity()
        try await client.configure(
            Self.configuration(),
            transport: transport,
            appAttestService: appAttest,
            credentialStore: store
        )

        _ = try await client.session()

        #expect(await appAttest.generateKeyCount == 2)
        #expect(await appAttest.attestationKeyIDs == ["key-123", "key-2"])
        #expect(await appAttest.assertionKeyIDs == ["key-123", "key-2"])
        #expect(await transport.registrationRequests.map(\.keyID) == [
            "key-123",
            "key-2",
        ])
        #expect(
            await store.keyRecord(for: "goodtides-ios")
                == AppIntegrityKeyRecord(keyID: "key-2", isRegistered: true)
        )
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

    @Test func sharedDelegatedGrantVectorHasIdenticalHashes() throws {
        let vector = try Self.loadDelegatedGrantVector()
        let tokens = try vector.tokenMaterial.map(Base64URL.decode)
        let tokenHashes = tokens.map { token in
            Base64URL.encode(Data(SHA256.hash(data: token)))
        }
        let requestBody = try Base64URL.decode(vector.consumption.requestBody)
        let changedRequestBody = try Base64URL.decode(
            vector.consumption.changedRequestBody
        )

        #expect(vector.protocolVersion == 1)
        #expect(tokenHashes == vector.expectedTokenHashes)
        #expect(
            Base64URL.encode(Data(SHA256.hash(data: requestBody)))
                == vector.consumption.requestDigest
        )
        #expect(
            Base64URL.encode(Data(SHA256.hash(data: changedRequestBody)))
                == vector.consumption.changedRequestDigest
        )
    }

    @Test func delegatedGrantPoolReservesExactRequestAndReplaysLocally() async throws {
        let vector = try Self.loadDelegatedGrantVector()
        let issuedAt = try #require(Self.parseDate(vector.issuedAt))
        let expiresAt = try #require(Self.parseDate(vector.expectedExpiresAt))
        let digest = try Base64URL.decode(vector.consumption.requestDigest)
        let changedDigest = try Base64URL.decode(
            vector.consumption.changedRequestDigest
        )
        let store = InMemoryAppIntegrityDelegatedGrantStore()
        let batch = AppIntegrityDelegatedGrantBatch(
            protocolVersion: vector.protocolVersion,
            applicationID: vector.authority.applicationID,
            environment: try #require(
                AppIntegrityEnvironment(rawValue: vector.authority.environment)
            ),
            operation: vector.policy.operation,
            grants: vector.tokenMaterial.map {
                AppIntegrityDelegatedGrantResponseItem(
                    token: $0,
                    expiresAt: expiresAt,
                    useLimit: vector.policy.useLimit
                )
            }
        )
        try await store.merge(
            batch,
            for: vector.authority.applicationID,
            at: issuedAt
        )

        let first = try #require(try await store.reserveGrant(
            for: vector.authority.applicationID,
            environment: batch.environment,
            operation: vector.policy.operation,
            submissionID: vector.consumption.submissionID,
            requestBodySHA256: digest,
            at: issuedAt
        ))
        let replay = try #require(try await store.reserveGrant(
            for: vector.authority.applicationID,
            environment: batch.environment,
            operation: vector.policy.operation,
            submissionID: vector.consumption.submissionID,
            requestBodySHA256: digest,
            at: issuedAt.addingTimeInterval(1)
        ))

        #expect(first == replay)
        #expect(first.token == vector.consumption.token)
        #expect(!String(describing: first).contains(first.token))
        #expect(!String(reflecting: first).contains(first.token))
        #expect(!String(describing: batch).contains(first.token))
        await #expect(throws: AppIntegrityDelegatedGrantStoreError.requestBindingMismatch) {
            try await store.reserveGrant(
                for: vector.authority.applicationID,
                environment: batch.environment,
                operation: vector.policy.operation,
                submissionID: vector.consumption.submissionID,
                requestBodySHA256: changedDigest,
                at: issuedAt.addingTimeInterval(2)
            )
        }
    }

    @Test func delegatedGrantPoolFailsClosedForInvalidOrExpiredAuthority() async throws {
        let vector = try Self.loadDelegatedGrantVector()
        let issuedAt = try #require(Self.parseDate(vector.issuedAt))
        let expiresAt = try #require(Self.parseDate(vector.expectedExpiresAt))
        let digest = try Base64URL.decode(vector.consumption.requestDigest)
        let store = InMemoryAppIntegrityDelegatedGrantStore()
        let invalidBatch = AppIntegrityDelegatedGrantBatch(
            protocolVersion: vector.protocolVersion,
            applicationID: vector.authority.applicationID,
            environment: .development,
            operation: vector.policy.operation,
            grants: [AppIntegrityDelegatedGrantResponseItem(
                token: vector.consumption.token,
                expiresAt: expiresAt,
                useLimit: 2
            )]
        )
        await #expect(throws: AppIntegrityDelegatedGrantStoreError.invalidBatch) {
            try await store.merge(
                invalidBatch,
                for: vector.authority.applicationID,
                at: issuedAt
            )
        }

        let validBatch = AppIntegrityDelegatedGrantBatch(
            protocolVersion: vector.protocolVersion,
            applicationID: vector.authority.applicationID,
            environment: .development,
            operation: vector.policy.operation,
            grants: [AppIntegrityDelegatedGrantResponseItem(
                token: vector.consumption.token,
                expiresAt: expiresAt,
                useLimit: 1
            )]
        )
        try await store.merge(validBatch, for: vector.authority.applicationID, at: issuedAt)

        let wrongEnvironment = try await store.reserveGrant(
            for: vector.authority.applicationID,
            environment: .production,
            operation: vector.policy.operation,
            submissionID: "wrong-environment",
            requestBodySHA256: digest,
            at: issuedAt
        )
        let expired = try await store.reserveGrant(
            for: vector.authority.applicationID,
            environment: .development,
            operation: vector.policy.operation,
            submissionID: "expired",
            requestBodySHA256: digest,
            at: expiresAt
        )

        #expect(wrongEnvironment == nil)
        #expect(expired == nil)
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

    private static func loadDelegatedGrantVector() throws -> DelegatedGrantVector {
        let repositoryRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let url = repositoryRoot
            .appendingPathComponent("Protocol")
            .appendingPathComponent("test-vectors")
            .appendingPathComponent("delegated-submission-grants-v1.json")
        return try JSONDecoder().decode(
            DelegatedGrantVector.self,
            from: Data(contentsOf: url)
        )
    }

    private static func parseDate(_ value: String) -> Date? {
        ISO8601DateFormatter().date(from: value)
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

private struct DelegatedGrantVector: Decodable {
    struct Authority: Decodable {
        let applicationID: String
        let environment: String
    }

    struct Policy: Decodable {
        let operation: String
        let useLimit: Int
    }

    struct Consumption: Decodable {
        let token: String
        let submissionID: String
        let requestBody: String
        let requestDigest: String
        let changedRequestBody: String
        let changedRequestDigest: String
    }

    let protocolVersion: Int
    let issuedAt: String
    let authority: Authority
    let policy: Policy
    let tokenMaterial: [String]
    let expectedTokenHashes: [String]
    let expectedExpiresAt: String
    let consumption: Consumption
}

private actor FakeAppAttestService: AppAttestServicing {
    let supported: Bool
    let operationDelay: Duration?
    private(set) var generateKeyCount = 0
    private(set) var attestationHashes: [Data] = []
    private(set) var assertionHashes: [Data] = []
    private(set) var attestationKeyIDs: [String] = []
    private(set) var assertionKeyIDs: [String] = []
    private var attestationFailures: [AppIntegrityError]
    private var assertionFailures: [AppIntegrityError]

    init(
        supported: Bool = true,
        operationDelay: Duration? = nil,
        attestationFailures: [AppIntegrityError] = [],
        assertionFailures: [AppIntegrityError] = []
    ) {
        self.supported = supported
        self.operationDelay = operationDelay
        self.attestationFailures = attestationFailures
        self.assertionFailures = assertionFailures
    }

    func isSupported() -> Bool {
        supported
    }

    func generateKey() async throws -> String {
        if let operationDelay {
            try await Task.sleep(for: operationDelay)
        }
        generateKeyCount += 1
        return generateKeyCount == 1 ? "key-123" : "key-\(generateKeyCount)"
    }

    func attestKey(_ keyID: String, clientDataHash: Data) async throws -> Data {
        if let operationDelay {
            try await Task.sleep(for: operationDelay)
        }
        attestationKeyIDs.append(keyID)
        attestationHashes.append(clientDataHash)
        if !attestationFailures.isEmpty {
            throw attestationFailures.removeFirst()
        }
        return Data("attestation".utf8)
    }

    func generateAssertion(_ keyID: String, clientDataHash: Data) async throws -> Data {
        if let operationDelay {
            try await Task.sleep(for: operationDelay)
        }
        assertionKeyIDs.append(keyID)
        assertionHashes.append(clientDataHash)
        if !assertionFailures.isEmpty {
            throw assertionFailures.removeFirst()
        }
        return Data("assertion".utf8)
    }
}

private actor FakeTransport: AppIntegrityTransport {
    private(set) var challengeRequests: [AppIntegrityChallengePurpose] = []
    private(set) var registrationRequests: [AppIntegrityAttestationRequest] = []
    private(set) var sessionRequests: [AppIntegritySessionRequest] = []
    private var registrationFailureCount: Int
    private let challengeDelay: Duration?

    init(
        registrationFailureCount: Int = 0,
        challengeDelay: Duration? = nil
    ) {
        self.registrationFailureCount = registrationFailureCount
        self.challengeDelay = challengeDelay
    }

    func requestChallenge(
        applicationID: String,
        purpose: AppIntegrityChallengePurpose
    ) async throws -> AppIntegrityChallenge {
        if let challengeDelay {
            try await Task.sleep(for: challengeDelay)
        }
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
