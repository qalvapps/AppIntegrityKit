import Foundation

public enum AppIntegrityEnvironment: String, Codable, Equatable, Sendable {
    case development
    case production
}

public struct AppIntegrityDelegatedGrantResponseItem: Codable, Equatable, Sendable,
    CustomStringConvertible, CustomDebugStringConvertible {
    public let token: String
    public let expiresAt: Date
    public let useLimit: Int

    public init(token: String, expiresAt: Date, useLimit: Int) {
        self.token = token
        self.expiresAt = expiresAt
        self.useLimit = useLimit
    }

    public var description: String {
        "AppIntegrityDelegatedGrantResponseItem(token: <redacted>, expiresAt: \(expiresAt), useLimit: \(useLimit))"
    }

    public var debugDescription: String { description }
}

public struct AppIntegrityDelegatedGrantBatch: Codable, Equatable, Sendable,
    CustomStringConvertible, CustomDebugStringConvertible {
    public let protocolVersion: Int
    public let applicationID: String
    public let environment: AppIntegrityEnvironment
    public let operation: String
    public let grants: [AppIntegrityDelegatedGrantResponseItem]

    public init(
        protocolVersion: Int,
        applicationID: String,
        environment: AppIntegrityEnvironment,
        operation: String,
        grants: [AppIntegrityDelegatedGrantResponseItem]
    ) {
        self.protocolVersion = protocolVersion
        self.applicationID = applicationID
        self.environment = environment
        self.operation = operation
        self.grants = grants
    }

    public var description: String {
        "AppIntegrityDelegatedGrantBatch(applicationID: \(applicationID), environment: \(environment.rawValue), operation: \(operation), grantCount: \(grants.count))"
    }

    public var debugDescription: String { description }
}

public struct AppIntegrityDelegatedGrantAuthorization: Equatable, Sendable,
    CustomStringConvertible, CustomDebugStringConvertible {
    public let token: String
    public let submissionID: String
    public let requestBodySHA256: Data
    public let expiresAt: Date

    public init(
        token: String,
        submissionID: String,
        requestBodySHA256: Data,
        expiresAt: Date
    ) {
        self.token = token
        self.submissionID = submissionID
        self.requestBodySHA256 = requestBodySHA256
        self.expiresAt = expiresAt
    }

    public var description: String {
        "AppIntegrityDelegatedGrantAuthorization(<redacted>, expiresAt: \(expiresAt))"
    }

    public var debugDescription: String { description }
}

public enum AppIntegrityDelegatedGrantStoreError: Error, Equatable, Sendable {
    case invalidBatch
    case invalidReservation
    case requestBindingMismatch
}
