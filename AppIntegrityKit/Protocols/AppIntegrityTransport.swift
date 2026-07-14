import Foundation

public protocol AppIntegrityTransport: Sendable {
    func requestChallenge(
        applicationID: String,
        purpose: AppIntegrityChallengePurpose
    ) async throws -> AppIntegrityChallenge

    func registerAttestation(
        _ request: AppIntegrityAttestationRequest
    ) async throws -> AppIntegrityAttestationResponse

    func establishSession(
        _ request: AppIntegritySessionRequest
    ) async throws -> AppIntegritySessionResponse
}

