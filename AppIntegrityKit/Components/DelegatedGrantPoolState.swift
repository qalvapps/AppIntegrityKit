import Foundation

struct AppIntegrityDelegatedGrantPoolRecord: Codable, Equatable, Sendable {
    private static let protocolVersion = 1
    private static let maximumGrantCount = 64

    struct Grant: Codable, Equatable, Sendable {
        let token: String
        let environment: AppIntegrityEnvironment
        let operation: String
        let expiresAt: Date
        let useLimit: Int
        var reservation: Reservation?
    }

    struct Reservation: Codable, Equatable, Sendable {
        let submissionID: String
        let requestBodySHA256: Data
    }

    var grants: [Grant]

    init(grants: [Grant] = []) {
        self.grants = grants
    }

    mutating func merge(
        _ batch: AppIntegrityDelegatedGrantBatch,
        expectedApplicationID: String,
        at date: Date
    ) throws {
        guard batch.protocolVersion == Self.protocolVersion,
              batch.applicationID == expectedApplicationID,
              Self.isBoundedASCII(batch.applicationID, maximum: 128),
              Self.isBoundedASCII(batch.operation, maximum: 128),
              batch.grants.count <= Self.maximumGrantCount else {
            throw AppIntegrityDelegatedGrantStoreError.invalidBatch
        }

        removeExpired(at: date)
        var responseTokens = Set<String>()
        for item in batch.grants {
            guard item.useLimit == 1,
                  item.expiresAt > date,
                  Self.isValidToken(item.token),
                  responseTokens.insert(item.token).inserted else {
                throw AppIntegrityDelegatedGrantStoreError.invalidBatch
            }

            if let existing = grants.first(where: { $0.token == item.token }) {
                guard existing.environment == batch.environment,
                      existing.operation == batch.operation,
                      existing.expiresAt == item.expiresAt,
                      existing.useLimit == item.useLimit else {
                    throw AppIntegrityDelegatedGrantStoreError.invalidBatch
                }
                continue
            }

            grants.append(Grant(
                token: item.token,
                environment: batch.environment,
                operation: batch.operation,
                expiresAt: item.expiresAt,
                useLimit: item.useLimit,
                reservation: nil
            ))
        }

        guard grants.count <= Self.maximumGrantCount else {
            throw AppIntegrityDelegatedGrantStoreError.invalidBatch
        }
        grants.sort {
            if $0.expiresAt != $1.expiresAt {
                return $0.expiresAt < $1.expiresAt
            }
            return $0.token < $1.token
        }
    }

    mutating func reserve(
        environment: AppIntegrityEnvironment,
        operation: String,
        submissionID: String,
        requestBodySHA256: Data,
        at date: Date
    ) throws -> AppIntegrityDelegatedGrantAuthorization? {
        guard Self.isBoundedASCII(operation, maximum: 128),
              Self.isBoundedASCII(submissionID, maximum: 256),
              requestBodySHA256.count == 32 else {
            throw AppIntegrityDelegatedGrantStoreError.invalidReservation
        }

        removeExpired(at: date)
        if let existing = grants.first(where: {
            $0.reservation?.submissionID == submissionID
        }) {
            guard existing.environment == environment,
                  existing.operation == operation,
                  existing.reservation?.requestBodySHA256 == requestBodySHA256 else {
                throw AppIntegrityDelegatedGrantStoreError.requestBindingMismatch
            }
            return Self.authorization(from: existing)
        }

        guard let index = grants.firstIndex(where: {
            $0.environment == environment
                && $0.operation == operation
                && $0.reservation == nil
        }) else {
            return nil
        }

        grants[index].reservation = Reservation(
            submissionID: submissionID,
            requestBodySHA256: requestBodySHA256
        )
        return Self.authorization(from: grants[index])
    }

    mutating func remove(token: String) {
        grants.removeAll { $0.token == token }
    }

    mutating func removeExpired(at date: Date) {
        grants.removeAll { $0.expiresAt <= date }
    }

    private static func authorization(
        from grant: Grant
    ) -> AppIntegrityDelegatedGrantAuthorization? {
        guard let reservation = grant.reservation else {
            return nil
        }
        return AppIntegrityDelegatedGrantAuthorization(
            token: grant.token,
            submissionID: reservation.submissionID,
            requestBodySHA256: reservation.requestBodySHA256,
            expiresAt: grant.expiresAt
        )
    }

    private static func isValidToken(_ token: String) -> Bool {
        guard token.count <= 512,
              let decoded = try? Base64URL.decode(token),
              decoded.count >= 32 else {
            return false
        }
        return Base64URL.encode(decoded) == token
    }

    private static func isBoundedASCII(_ value: String, maximum: Int) -> Bool {
        !value.isEmpty
            && value.utf8.count <= maximum
            && value.unicodeScalars.allSatisfy(\.isASCII)
    }
}
