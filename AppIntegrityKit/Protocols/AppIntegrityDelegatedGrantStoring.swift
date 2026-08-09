import Foundation

public protocol AppIntegrityDelegatedGrantStoring: Sendable {
    func merge(
        _ batch: AppIntegrityDelegatedGrantBatch,
        for applicationID: String,
        at date: Date
    ) async throws

    func reserveGrant(
        for applicationID: String,
        environment: AppIntegrityEnvironment,
        operation: String,
        submissionID: String,
        requestBodySHA256: Data,
        at date: Date
    ) async throws -> AppIntegrityDelegatedGrantAuthorization?

    func removeGrant(token: String, for applicationID: String) async throws
    func removeExpiredGrants(for applicationID: String, at date: Date) async throws
    func removeAllGrants(for applicationID: String) async throws
}
public extension AppIntegrityDelegatedGrantStoring {
    func merge(
        _ batch: AppIntegrityDelegatedGrantBatch,
        for applicationID: String
    ) async throws {
        try await merge(batch, for: applicationID, at: .now)
    }

    func reserveGrant(
        for applicationID: String,
        environment: AppIntegrityEnvironment,
        operation: String,
        submissionID: String,
        requestBodySHA256: Data
    ) async throws -> AppIntegrityDelegatedGrantAuthorization? {
        try await reserveGrant(
            for: applicationID,
            environment: environment,
            operation: operation,
            submissionID: submissionID,
            requestBodySHA256: requestBodySHA256,
            at: .now
        )
    }

    func removeExpiredGrants(for applicationID: String) async throws {
        try await removeExpiredGrants(for: applicationID, at: .now)
    }
}
