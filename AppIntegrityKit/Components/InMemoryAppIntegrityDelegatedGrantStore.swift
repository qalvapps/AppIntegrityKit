import Foundation

public actor InMemoryAppIntegrityDelegatedGrantStore: AppIntegrityDelegatedGrantStoring {
    private var pools: [String: AppIntegrityDelegatedGrantPoolRecord] = [:]

    public init() {}

    public func merge(
        _ batch: AppIntegrityDelegatedGrantBatch,
        for applicationID: String,
        at date: Date
    ) throws {
        var pool = pools[applicationID] ?? AppIntegrityDelegatedGrantPoolRecord()
        try pool.merge(batch, expectedApplicationID: applicationID, at: date)
        pools[applicationID] = pool
    }

    public func reserveGrant(
        for applicationID: String,
        environment: AppIntegrityEnvironment,
        operation: String,
        submissionID: String,
        requestBodySHA256: Data,
        at date: Date
    ) throws -> AppIntegrityDelegatedGrantAuthorization? {
        var pool = pools[applicationID] ?? AppIntegrityDelegatedGrantPoolRecord()
        let authorization = try pool.reserve(
            environment: environment,
            operation: operation,
            submissionID: submissionID,
            requestBodySHA256: requestBodySHA256,
            at: date
        )
        pools[applicationID] = pool
        return authorization
    }

    public func removeGrant(token: String, for applicationID: String) {
        var pool = pools[applicationID] ?? AppIntegrityDelegatedGrantPoolRecord()
        pool.remove(token: token)
        pools[applicationID] = pool
    }

    public func removeExpiredGrants(for applicationID: String, at date: Date) {
        var pool = pools[applicationID] ?? AppIntegrityDelegatedGrantPoolRecord()
        pool.removeExpired(at: date)
        pools[applicationID] = pool
    }

    public func removeAllGrants(for applicationID: String) {
        pools.removeValue(forKey: applicationID)
    }
}
