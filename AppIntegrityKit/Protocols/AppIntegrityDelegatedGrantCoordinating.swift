import Foundation

/// Product-neutral exclusion around one complete delegated-grant pool mutation.
///
/// Coordination state must never contain grant or product authority material.
public protocol AppIntegrityDelegatedGrantCoordinating: Sendable {
    var capabilityVersion: Int { get }

    func withExclusiveAccess<Result>(
        _ operation: () throws -> Result
    ) throws -> Result
}

/// Capability surfaced by stores that are safe to share across processes.
public protocol AppIntegrityCoordinatedDelegatedGrantStoring:
    AppIntegrityDelegatedGrantStoring {
    var coordinationCapabilityVersion: Int { get }
}
