import Foundation

/// Stable, non-localized keys that a consuming app can map to its own copy.
public enum AppIntegrityErrorCode: String, Equatable, Sendable {
    case notConfigured = "not_configured"
    case invalidConfiguration = "invalid_configuration"
    case appAttestNotSupported = "app_attest_not_supported"
    case invalidChallenge = "invalid_challenge"
    case unsupportedProtocolVersion = "unsupported_protocol_version"
    case registrationRejected = "registration_rejected"
    case entitlementEvidenceTooLarge = "entitlement_evidence_too_large"
    case missingDeviceCheckResult = "missing_device_check_result"
    case appAttestServerUnavailable = "app_attest_server_unavailable"
    case appAttestKeyRejected = "app_attest_key_rejected"
    case appAttestFailure = "app_attest_failure"
    case credentialStoreFailure = "credential_store_failure"
    case transportFailure = "transport_failure"
    case invalidServerResponse = "invalid_server_response"
}

/// Typed integrity failures. This deliberately does not conform to
/// `LocalizedError`: AppIntegrityKit has no product UI and consuming apps own
/// all user-facing wording and localization.
public enum AppIntegrityError: Error, Equatable, Sendable {
    case notConfigured
    case invalidConfiguration(String)
    case appAttestNotSupported
    case invalidChallenge(String)
    case unsupportedProtocolVersion(Int)
    case registrationRejected
    case entitlementEvidenceTooLarge
    case missingDeviceCheckResult
    case appAttestServerUnavailable
    case appAttestKeyRejected
    case appAttestFailure(Int)
    case credentialStoreFailure(Int32)
    case transportFailure(statusCode: Int, code: String?)
    case invalidServerResponse

    public var code: AppIntegrityErrorCode {
        switch self {
        case .notConfigured:
            .notConfigured
        case .invalidConfiguration:
            .invalidConfiguration
        case .appAttestNotSupported:
            .appAttestNotSupported
        case .invalidChallenge:
            .invalidChallenge
        case .unsupportedProtocolVersion:
            .unsupportedProtocolVersion
        case .registrationRejected:
            .registrationRejected
        case .entitlementEvidenceTooLarge:
            .entitlementEvidenceTooLarge
        case .missingDeviceCheckResult:
            .missingDeviceCheckResult
        case .appAttestServerUnavailable:
            .appAttestServerUnavailable
        case .appAttestKeyRejected:
            .appAttestKeyRejected
        case .appAttestFailure:
            .appAttestFailure
        case .credentialStoreFailure:
            .credentialStoreFailure
        case .transportFailure:
            .transportFailure
        case .invalidServerResponse:
            .invalidServerResponse
        }
    }

    /// HTTP status returned by the product edge, when this is a transport
    /// failure. The consuming app decides how (or whether) to present it.
    public var httpStatusCode: Int? {
        guard case .transportFailure(let statusCode, _) = self else { return nil }
        return statusCode
    }

    /// Safe machine-readable code returned by the product edge, when present.
    public var backendCode: String? {
        guard case .transportFailure(_, let code) = self else { return nil }
        return code
    }
}
