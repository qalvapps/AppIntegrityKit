import Foundation
import Security

public actor KeychainAppIntegrityCredentialStore: AppIntegrityCredentialStoring {
    private let service: String
    private let accessGroup: String?

    public init(service: String, accessGroup: String? = nil) {
        self.service = service
        self.accessGroup = accessGroup
    }

    public func keyRecord(for applicationID: String) throws -> AppIntegrityKeyRecord? {
        try read(AppIntegrityKeyRecord.self, account: keyAccount(applicationID))
    }

    public func saveKeyRecord(_ record: AppIntegrityKeyRecord, for applicationID: String) throws {
        try write(record, account: keyAccount(applicationID))
    }

    public func session(for applicationID: String) throws -> AppIntegritySession? {
        try read(AppIntegritySession.self, account: sessionAccount(applicationID))
    }

    public func saveSession(_ session: AppIntegritySession, for applicationID: String) throws {
        try write(session, account: sessionAccount(applicationID))
    }

    public func removeSession(for applicationID: String) throws {
        try remove(account: sessionAccount(applicationID))
    }

    public func removeAll(for applicationID: String) throws {
        try remove(account: keyAccount(applicationID))
        try remove(account: sessionAccount(applicationID))
    }

    private func keyAccount(_ applicationID: String) -> String {
        "key.\(applicationID)"
    }

    private func sessionAccount(_ applicationID: String) -> String {
        "session.\(applicationID)"
    }

    private func baseQuery(account: String) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        if let accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        return query
    }

    private func read<Value: Decodable>(_ type: Value.Type, account: String) throws -> Value? {
        var query = baseQuery(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess, let data = result as? Data else {
            throw AppIntegrityError.credentialStoreFailure(status)
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        return try decoder.decode(type, from: data)
    }

    private func write<Value: Encodable>(_ value: Value, account: String) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .millisecondsSince1970
        let data = try encoder.encode(value)
        let query = baseQuery(account: account)
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

    private func remove(account: String) throws {
        let status = SecItemDelete(baseQuery(account: account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw AppIntegrityError.credentialStoreFailure(status)
        }
    }
}

