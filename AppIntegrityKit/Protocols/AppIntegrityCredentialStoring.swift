import Foundation

public protocol AppIntegrityCredentialStoring: Sendable {
    func keyRecord(for applicationID: String) async throws -> AppIntegrityKeyRecord?
    func saveKeyRecord(_ record: AppIntegrityKeyRecord, for applicationID: String) async throws
    func session(for applicationID: String) async throws -> AppIntegritySession?
    func saveSession(_ session: AppIntegritySession, for applicationID: String) async throws
    func removeSession(for applicationID: String) async throws
    func removeAll(for applicationID: String) async throws
}

