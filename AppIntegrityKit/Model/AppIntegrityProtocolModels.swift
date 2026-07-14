import Foundation

public enum AppIntegrityChallengePurpose: String, Codable, Equatable, Sendable {
    case attestation
    case session
}

public struct AppIntegrityChallenge: Codable, Equatable, Sendable {
    public let protocolVersion: Int
    public let challengeID: String
    public let challenge: String
    public let purpose: AppIntegrityChallengePurpose
    public let expiresAt: Date

    public init(
        protocolVersion: Int,
        challengeID: String,
        challenge: String,
        purpose: AppIntegrityChallengePurpose,
        expiresAt: Date
    ) {
        self.protocolVersion = protocolVersion
        self.challengeID = challengeID
        self.challenge = challenge
        self.purpose = purpose
        self.expiresAt = expiresAt
    }
}

public struct AppIntegrityAttestationRequest: Codable, Equatable, Sendable {
    public let protocolVersion: Int
    public let applicationID: String
    public let challengeID: String
    public let keyID: String
    public let attestationObject: String

    public init(
        protocolVersion: Int,
        applicationID: String,
        challengeID: String,
        keyID: String,
        attestationObject: String
    ) {
        self.protocolVersion = protocolVersion
        self.applicationID = applicationID
        self.challengeID = challengeID
        self.keyID = keyID
        self.attestationObject = attestationObject
    }
}

public struct AppIntegrityAttestationResponse: Codable, Equatable, Sendable {
    public let protocolVersion: Int
    public let registered: Bool

    public init(protocolVersion: Int, registered: Bool) {
        self.protocolVersion = protocolVersion
        self.registered = registered
    }
}

public struct AppIntegritySessionClientData: Codable, Equatable, Sendable {
    public let applicationID: String
    public let challenge: String
    public let challengeID: String
    public let entitlementEvidenceSHA256: String?
    public let keyID: String
    public let protocolVersion: Int
    public let requestedScopes: [String]

    public init(
        applicationID: String,
        challenge: String,
        challengeID: String,
        entitlementEvidenceSHA256: String?,
        keyID: String,
        protocolVersion: Int,
        requestedScopes: [String]
    ) {
        self.applicationID = applicationID
        self.challenge = challenge
        self.challengeID = challengeID
        self.entitlementEvidenceSHA256 = entitlementEvidenceSHA256
        self.keyID = keyID
        self.protocolVersion = protocolVersion
        self.requestedScopes = Array(Set(requestedScopes)).sorted()
    }
}

public struct AppIntegritySessionRequest: Codable, Equatable, Sendable {
    public let protocolVersion: Int
    public let applicationID: String
    public let keyID: String
    public let clientData: String
    public let assertion: String
    public let entitlementEvidence: String?

    public init(
        protocolVersion: Int,
        applicationID: String,
        keyID: String,
        clientData: String,
        assertion: String,
        entitlementEvidence: String?
    ) {
        self.protocolVersion = protocolVersion
        self.applicationID = applicationID
        self.keyID = keyID
        self.clientData = clientData
        self.assertion = assertion
        self.entitlementEvidence = entitlementEvidence
    }
}

public struct AppIntegritySessionResponse: Codable, Equatable, Sendable {
    public let protocolVersion: Int
    public let sessionToken: String
    public let expiresAt: Date
    public let scopes: [String]

    public init(
        protocolVersion: Int,
        sessionToken: String,
        expiresAt: Date,
        scopes: [String]
    ) {
        self.protocolVersion = protocolVersion
        self.sessionToken = sessionToken
        self.expiresAt = expiresAt
        self.scopes = Array(Set(scopes)).sorted()
    }
}

public struct AppIntegritySession: Codable, Equatable, Sendable {
    public let token: String
    public let expiresAt: Date
    public let scopes: [String]

    public init(token: String, expiresAt: Date, scopes: [String]) {
        self.token = token
        self.expiresAt = expiresAt
        self.scopes = Array(Set(scopes)).sorted()
    }

    public func isUsable(
        at date: Date = .now,
        refreshLeeway: TimeInterval,
        requiredScopes: Set<String>
    ) -> Bool {
        expiresAt.timeIntervalSince(date) > refreshLeeway
            && requiredScopes.isSubset(of: Set(scopes))
    }
}

public struct AppIntegrityKeyRecord: Codable, Equatable, Sendable {
    public let keyID: String
    public let isRegistered: Bool

    public init(keyID: String, isRegistered: Bool) {
        self.keyID = keyID
        self.isRegistered = isRegistered
    }
}

