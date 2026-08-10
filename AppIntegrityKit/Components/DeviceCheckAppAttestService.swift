#if canImport(DeviceCheck)
import DeviceCheck
import Foundation

@available(iOS 14.0, macOS 11.0, watchOS 9.0, *)
public actor DeviceCheckAppAttestService: AppAttestServicing {
    private enum Operation: Equatable {
        case keyGeneration
        case attestation
        case assertion
    }

    private let service: DCAppAttestService

    public init(service: DCAppAttestService = .shared) {
        self.service = service
    }

    public func isSupported() -> Bool {
        service.isSupported
    }

    public func generateKey() async throws -> String {
        try await withCheckedThrowingContinuation { continuation in
            service.generateKey { keyID, error in
                if let error {
                    continuation.resume(throwing: Self.map(error, operation: .keyGeneration))
                } else if let keyID {
                    continuation.resume(returning: keyID)
                } else {
                    continuation.resume(throwing: AppIntegrityError.missingDeviceCheckResult)
                }
            }
        }
    }

    public func attestKey(_ keyID: String, clientDataHash: Data) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            service.attestKey(keyID, clientDataHash: clientDataHash) { object, error in
                if let error {
                    continuation.resume(throwing: Self.map(error, operation: .attestation))
                } else if let object {
                    continuation.resume(returning: object)
                } else {
                    continuation.resume(throwing: AppIntegrityError.missingDeviceCheckResult)
                }
            }
        }
    }

    public func generateAssertion(_ keyID: String, clientDataHash: Data) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            service.generateAssertion(keyID, clientDataHash: clientDataHash) { assertion, error in
                if let error {
                    continuation.resume(throwing: Self.map(error, operation: .assertion))
                } else if let assertion {
                    continuation.resume(returning: assertion)
                } else {
                    continuation.resume(throwing: AppIntegrityError.missingDeviceCheckResult)
                }
            }
        }
    }

    private nonisolated static func map(
        _ error: Error,
        operation: Operation
    ) -> Error {
        let nsError = error as NSError
        guard nsError.domain == DCError.errorDomain else { return error }

        if nsError.code == DCError.Code.featureUnsupported.rawValue {
            return AppIntegrityError.appAttestNotSupported
        }
        if nsError.code == DCError.Code.serverUnavailable.rawValue {
            return AppIntegrityError.appAttestServerUnavailable
        }
        if operation == .attestation
            || nsError.code == DCError.Code.invalidKey.rawValue {
            return AppIntegrityError.appAttestKeyRejected
        }
        return AppIntegrityError.appAttestFailure(nsError.code)
    }
}
#endif
