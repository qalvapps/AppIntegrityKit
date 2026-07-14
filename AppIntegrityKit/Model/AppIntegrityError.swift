import Foundation

public enum AppIntegrityError: Error, Equatable, LocalizedError, Sendable {
    case notConfigured
    case invalidConfiguration(String)
    case appAttestNotSupported
    case invalidChallenge(String)
    case unsupportedProtocolVersion(Int)
    case registrationRejected
    case entitlementEvidenceTooLarge
    case missingDeviceCheckResult
    case credentialStoreFailure(Int32)
    case transportFailure(statusCode: Int, code: String?)
    case invalidServerResponse

    public var errorDescription: String? {
        switch self {
        case .notConfigured:
            "AppIntegrityKit has not been configured."
        case .invalidConfiguration(let reason):
            "Invalid AppIntegrityKit configuration: \(reason)"
        case .appAttestNotSupported:
            "App Attest is not supported on this device or surface."
        case .invalidChallenge(let reason):
            "The integrity challenge is invalid: \(reason)"
        case .unsupportedProtocolVersion(let version):
            "Unsupported AppIntegrity protocol version: \(version)."
        case .registrationRejected:
            "The backend rejected the App Attest registration."
        case .entitlementEvidenceTooLarge:
            "Entitlement evidence exceeds the 256 KiB protocol limit."
        case .missingDeviceCheckResult:
            "DeviceCheck completed without returning a result."
        case .credentialStoreFailure(let status):
            "The integrity credential store failed with status \(status)."
        case .transportFailure(let statusCode, let code):
            if let code {
                "The integrity backend returned HTTP \(statusCode) (\(code))."
            } else {
                "The integrity backend returned HTTP \(statusCode)."
            }
        case .invalidServerResponse:
            "The integrity backend returned an invalid response."
        }
    }
}
