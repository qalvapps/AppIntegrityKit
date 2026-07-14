import CryptoKit
import Foundation

enum SessionClientDataEncoder {
    static func makeClientData(
        configuration: AppIntegrityConfiguration,
        challenge: AppIntegrityChallenge,
        keyID: String,
        entitlementEvidence: Data?
    ) throws -> (model: AppIntegritySessionClientData, encoded: Data) {
        let evidenceHash = entitlementEvidence.map {
            Base64URL.encode(Data(SHA256.hash(data: $0)))
        }
        let model = AppIntegritySessionClientData(
            applicationID: configuration.applicationID,
            challenge: challenge.challenge,
            challengeID: challenge.challengeID,
            entitlementEvidenceSHA256: evidenceHash,
            keyID: keyID,
            protocolVersion: AppIntegrityConfiguration.protocolVersion,
            requestedScopes: Array(configuration.requestedScopes)
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return (model, try encoder.encode(model))
    }
}

