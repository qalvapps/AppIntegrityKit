import Foundation

public actor InMemoryAppIntegrityCredentialStore: AppIntegrityCredentialStoring {
    private var keyRecords: [String: AppIntegrityKeyRecord] = [:]
    private var sessions: [String: AppIntegritySession] = [:]

    public init() {}

    public func keyRecord(for applicationID: String) -> AppIntegrityKeyRecord? {
        keyRecords[applicationID]
    }

    public func saveKeyRecord(_ record: AppIntegrityKeyRecord, for applicationID: String) {
        keyRecords[applicationID] = record
    }

    public func session(for applicationID: String) -> AppIntegritySession? {
        sessions[applicationID]
    }

    public func saveSession(_ session: AppIntegritySession, for applicationID: String) {
        sessions[applicationID] = session
    }

    public func removeSession(for applicationID: String) {
        sessions.removeValue(forKey: applicationID)
    }

    public func removeAll(for applicationID: String) {
        keyRecords.removeValue(forKey: applicationID)
        sessions.removeValue(forKey: applicationID)
    }
}

