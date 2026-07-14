import Foundation

public final class AppIntegrity: Sendable {
    public static let shared = AppIntegrity()
    public static let version = "0.1.0-dev"

    private let state = AppIntegrityState()

    public init() {}

    public func configure(_ configuration: AppIntegrityConfiguration) async throws {
        #if canImport(DeviceCheck)
        try await state.configure(
            configuration: configuration,
            transport: URLSessionAppIntegrityTransport(baseURL: configuration.apiBaseURL),
            appAttestService: DeviceCheckAppAttestService(),
            credentialStore: KeychainAppIntegrityCredentialStore(
                service: configuration.keychainService,
                accessGroup: configuration.keychainAccessGroup
            )
        )
        #else
        throw AppIntegrityError.appAttestNotSupported
        #endif
    }

    public func configure(
        _ configuration: AppIntegrityConfiguration,
        transport: any AppIntegrityTransport,
        appAttestService: any AppAttestServicing,
        credentialStore: any AppIntegrityCredentialStoring
    ) async throws {
        try await state.configure(
            configuration: configuration,
            transport: transport,
            appAttestService: appAttestService,
            credentialStore: credentialStore
        )
    }

    public func configuration() async -> AppIntegrityConfiguration? {
        await state.configuration()
    }

    public func session(
        entitlementEvidence: Data? = nil,
        forceRefresh: Bool = false
    ) async throws -> AppIntegritySession {
        try await state.session(
            entitlementEvidence: entitlementEvidence,
            forceRefresh: forceRefresh
        )
    }

    public func invalidateSession() async throws {
        try await state.invalidateSession()
    }

    public func resetRegistration() async throws {
        try await state.resetRegistration()
    }
}

