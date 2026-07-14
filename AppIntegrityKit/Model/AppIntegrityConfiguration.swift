import Foundation

public struct AppIntegrityConfiguration: Equatable, Sendable {
    public static let protocolVersion = 1

    public let applicationID: String
    public let apiBaseURL: URL
    public let requestedScopes: Set<String>
    public let sessionRefreshLeeway: TimeInterval
    public let keychainService: String
    public let keychainAccessGroup: String?

    public init(
        applicationID: String,
        apiBaseURL: URL,
        requestedScopes: Set<String>,
        sessionRefreshLeeway: TimeInterval = 60,
        keychainService: String = "com.qalvapps.AppIntegrityKit",
        keychainAccessGroup: String? = nil
    ) {
        self.applicationID = applicationID
        self.apiBaseURL = apiBaseURL
        self.requestedScopes = requestedScopes
        self.sessionRefreshLeeway = sessionRefreshLeeway
        self.keychainService = keychainService
        self.keychainAccessGroup = keychainAccessGroup
    }
}

