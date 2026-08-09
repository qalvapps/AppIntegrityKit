import Foundation
import Security

public actor KeychainAppIntegrityDelegatedGrantStore: AppIntegrityDelegatedGrantStoring {
    private let service: String
    private let accessGroup: String?

    public init(service: String, accessGroup: String? = nil) {
        self.service = service
        self.accessGroup = accessGroup
    }

    public func merge(
        _ batch: AppIntegrityDelegatedGrantBatch,
        for applicationID: String,
        at date: Date
    ) throws {
        var pool = try readPool(for: applicationID)
        try pool.merge(batch, expectedApplicationID: applicationID, at: date)
        try writePool(pool, for: applicationID)
    }

    public func reserveGrant(
        for applicationID: String,
        environment: AppIntegrityEnvironment,
        operation: String,
        submissionID: String,
        requestBodySHA256: Data,
        at date: Date
    ) throws -> AppIntegrityDelegatedGrantAuthorization? {
        var pool = try readPool(for: applicationID)
        let authorization = try pool.reserve(
            environment: environment,
            operation: operation,
            submissionID: submissionID,
            requestBodySHA256: requestBodySHA256,
            at: date
        )
        try writePool(pool, for: applicationID)
        return authorization
    }

    public func removeGrant(token: String, for applicationID: String) throws {
        var pool = try readPool(for: applicationID)
        pool.remove(token: token)
        try writePool(pool, for: applicationID)
    }

    public func removeExpiredGrants(for applicationID: String, at date: Date) throws {
        var pool = try readPool(for: applicationID)
        pool.removeExpired(at: date)
        try writePool(pool, for: applicationID)
    }

    public func removeAllGrants(for applicationID: String) throws {
        let status = SecItemDelete(baseQuery(for: applicationID) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw AppIntegrityError.credentialStoreFailure(status)
        }
    }

    private func readPool(for applicationID: String) throws -> AppIntegrityDelegatedGrantPoolRecord {
        var query = baseQuery(for: applicationID)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return AppIntegrityDelegatedGrantPoolRecord()
        }
        guard status == errSecSuccess, let data = result as? Data else {
            throw AppIntegrityError.credentialStoreFailure(status)
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        return try decoder.decode(AppIntegrityDelegatedGrantPoolRecord.self, from: data)
    }

    private func writePool(
        _ pool: AppIntegrityDelegatedGrantPoolRecord,
        for applicationID: String
    ) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .millisecondsSince1970
        let data = try encoder.encode(pool)
        let query = baseQuery(for: applicationID)
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]

        let updateStatus = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if updateStatus == errSecSuccess {
            return
        }
        guard updateStatus == errSecItemNotFound else {
            throw AppIntegrityError.credentialStoreFailure(updateStatus)
        }

        var addition = query
        attributes.forEach { addition[$0.key] = $0.value }
        let addStatus = SecItemAdd(addition as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw AppIntegrityError.credentialStoreFailure(addStatus)
        }
    }

    private func baseQuery(for applicationID: String) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "delegated-grants.\(applicationID)"
        ]
        if let accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        return query
    }
}
