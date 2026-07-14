import CryptoKit
import Foundation

actor AppIntegrityState {
    private struct Runtime: Sendable {
        let configuration: AppIntegrityConfiguration
        let transport: any AppIntegrityTransport
        let appAttestService: any AppAttestServicing
        let credentialStore: any AppIntegrityCredentialStoring
    }

    private var runtime: Runtime?

    func configure(
        configuration: AppIntegrityConfiguration,
        transport: any AppIntegrityTransport,
        appAttestService: any AppAttestServicing,
        credentialStore: any AppIntegrityCredentialStoring
    ) throws {
        try validate(configuration)
        runtime = Runtime(
            configuration: configuration,
            transport: transport,
            appAttestService: appAttestService,
            credentialStore: credentialStore
        )
    }

    func configuration() -> AppIntegrityConfiguration? {
        runtime?.configuration
    }

    func session(
        entitlementEvidence: Data?,
        forceRefresh: Bool
    ) async throws -> AppIntegritySession {
        guard let runtime else {
            throw AppIntegrityError.notConfigured
        }
        if let entitlementEvidence, entitlementEvidence.count > 256 * 1_024 {
            throw AppIntegrityError.entitlementEvidenceTooLarge
        }

        let configuration = runtime.configuration
        if !forceRefresh,
           let stored = try await runtime.credentialStore.session(
               for: configuration.applicationID
           ),
           stored.isUsable(
               refreshLeeway: configuration.sessionRefreshLeeway,
               requiredScopes: configuration.requestedScopes
           ) {
            return stored
        }

        guard await runtime.appAttestService.isSupported() else {
            throw AppIntegrityError.appAttestNotSupported
        }

        let keyRecord = try await registeredKey(using: runtime)
        let challenge = try await runtime.transport.requestChallenge(
            applicationID: configuration.applicationID,
            purpose: .session
        )
        try validate(challenge, expectedPurpose: .session)

        let clientData = try SessionClientDataEncoder.makeClientData(
            configuration: configuration,
            challenge: challenge,
            keyID: keyRecord.keyID,
            entitlementEvidence: entitlementEvidence
        ).encoded
        let clientDataHash = Data(SHA256.hash(data: clientData))
        let assertion = try await runtime.appAttestService.generateAssertion(
            keyRecord.keyID,
            clientDataHash: clientDataHash
        )
        let request = AppIntegritySessionRequest(
            protocolVersion: AppIntegrityConfiguration.protocolVersion,
            applicationID: configuration.applicationID,
            keyID: keyRecord.keyID,
            clientData: Base64URL.encode(clientData),
            assertion: Base64URL.encode(assertion),
            entitlementEvidence: entitlementEvidence.map(Base64URL.encode)
        )
        let response = try await runtime.transport.establishSession(request)
        try validateProtocolVersion(response.protocolVersion)
        guard !response.sessionToken.isEmpty,
              response.sessionToken.count <= 4_096,
              response.scopes.allSatisfy({ Self.isValidIdentifier($0, maximum: 128) }) else {
            throw AppIntegrityError.invalidServerResponse
        }

        let session = AppIntegritySession(
            token: response.sessionToken,
            expiresAt: response.expiresAt,
            scopes: response.scopes
        )
        guard session.isUsable(
            refreshLeeway: configuration.sessionRefreshLeeway,
            requiredScopes: configuration.requestedScopes
        ) else {
            throw AppIntegrityError.invalidServerResponse
        }
        try await runtime.credentialStore.saveSession(
            session,
            for: configuration.applicationID
        )
        return session
    }

    func invalidateSession() async throws {
        guard let runtime else {
            throw AppIntegrityError.notConfigured
        }
        try await runtime.credentialStore.removeSession(
            for: runtime.configuration.applicationID
        )
    }

    func resetRegistration() async throws {
        guard let runtime else {
            throw AppIntegrityError.notConfigured
        }
        try await runtime.credentialStore.removeAll(
            for: runtime.configuration.applicationID
        )
    }

    private func registeredKey(using runtime: Runtime) async throws -> AppIntegrityKeyRecord {
        let applicationID = runtime.configuration.applicationID
        var record = try await runtime.credentialStore.keyRecord(for: applicationID)
        if record == nil {
            let keyID = try await runtime.appAttestService.generateKey()
            guard Self.isASCII(keyID), !keyID.isEmpty, keyID.count <= 1_024 else {
                throw AppIntegrityError.missingDeviceCheckResult
            }
            let pending = AppIntegrityKeyRecord(keyID: keyID, isRegistered: false)
            try await runtime.credentialStore.saveKeyRecord(pending, for: applicationID)
            record = pending
        }

        guard let record else {
            throw AppIntegrityError.missingDeviceCheckResult
        }
        if record.isRegistered {
            return record
        }

        let challenge = try await runtime.transport.requestChallenge(
            applicationID: applicationID,
            purpose: .attestation
        )
        try validate(challenge, expectedPurpose: .attestation)
        let challengeData = try Base64URL.decode(challenge.challenge)
        let attestation = try await runtime.appAttestService.attestKey(
            record.keyID,
            clientDataHash: Data(SHA256.hash(data: challengeData))
        )
        let response = try await runtime.transport.registerAttestation(
            AppIntegrityAttestationRequest(
                protocolVersion: AppIntegrityConfiguration.protocolVersion,
                applicationID: applicationID,
                challengeID: challenge.challengeID,
                keyID: record.keyID,
                attestationObject: Base64URL.encode(attestation)
            )
        )
        try validateProtocolVersion(response.protocolVersion)
        guard response.registered else {
            throw AppIntegrityError.registrationRejected
        }

        let registered = AppIntegrityKeyRecord(keyID: record.keyID, isRegistered: true)
        try await runtime.credentialStore.saveKeyRecord(registered, for: applicationID)
        return registered
    }

    private func validate(_ configuration: AppIntegrityConfiguration) throws {
        guard !configuration.applicationID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw AppIntegrityError.invalidConfiguration("applicationID is empty")
        }
        let scheme = configuration.apiBaseURL.scheme?.lowercased()
        let isLocalHTTP = scheme == "http"
            && ["localhost", "127.0.0.1"].contains(configuration.apiBaseURL.host)
        guard scheme == "https" || isLocalHTTP else {
            throw AppIntegrityError.invalidConfiguration("apiBaseURL must use HTTPS")
        }
        guard configuration.apiBaseURL.host != nil,
              configuration.apiBaseURL.user == nil,
              configuration.apiBaseURL.password == nil,
              configuration.apiBaseURL.query == nil,
              configuration.apiBaseURL.fragment == nil else {
            throw AppIntegrityError.invalidConfiguration("apiBaseURL contains unsupported components")
        }
        guard Self.isValidIdentifier(configuration.applicationID, maximum: 128) else {
            throw AppIntegrityError.invalidConfiguration("applicationID is invalid")
        }
        guard !configuration.requestedScopes.isEmpty,
              configuration.requestedScopes.allSatisfy({
                  Self.isValidIdentifier($0, maximum: 128)
              }) else {
            throw AppIntegrityError.invalidConfiguration("requestedScopes must not be empty")
        }
        guard configuration.sessionRefreshLeeway >= 0 else {
            throw AppIntegrityError.invalidConfiguration("sessionRefreshLeeway is negative")
        }
    }

    private func validate(
        _ challenge: AppIntegrityChallenge,
        expectedPurpose: AppIntegrityChallengePurpose
    ) throws {
        try validateProtocolVersion(challenge.protocolVersion)
        guard challenge.purpose == expectedPurpose else {
            throw AppIntegrityError.invalidChallenge("purpose mismatch")
        }
        guard challenge.expiresAt > .now else {
            throw AppIntegrityError.invalidChallenge("challenge expired")
        }
        guard !challenge.challengeID.isEmpty,
              challenge.challengeID.count <= 256,
              Self.isASCII(challenge.challengeID) else {
            throw AppIntegrityError.invalidChallenge("challenge ID is invalid")
        }
        let challengeData = try Base64URL.decode(challenge.challenge)
        guard challengeData.count >= 32 else {
            throw AppIntegrityError.invalidChallenge("challenge has insufficient entropy")
        }
    }

    private func validateProtocolVersion(_ version: Int) throws {
        guard version == AppIntegrityConfiguration.protocolVersion else {
            throw AppIntegrityError.unsupportedProtocolVersion(version)
        }
    }

    private static func isValidIdentifier(_ value: String, maximum: Int) -> Bool {
        !value.isEmpty
            && value.count <= maximum
            && isASCII(value)
            && value.range(
                of: #"^[A-Za-z0-9][A-Za-z0-9._:-]*$"#,
                options: .regularExpression
            ) != nil
    }

    private static func isASCII(_ value: String) -> Bool {
        value.unicodeScalars.allSatisfy(\.isASCII)
    }
}
