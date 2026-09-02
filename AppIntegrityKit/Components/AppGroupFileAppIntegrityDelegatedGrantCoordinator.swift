import Darwin
import Foundation

public enum AppIntegrityDelegatedGrantCoordinationError: Error, Equatable, Sendable {
    case invalidConfiguration
    case unavailable(Int32)
    case timedOut
}

/// A bounded, process-shared lock whose file contains no authority material.
public struct AppGroupFileAppIntegrityDelegatedGrantCoordinator:
    AppIntegrityDelegatedGrantCoordinating, Sendable {
    public let capabilityVersion = 1

    private let lockFileURL: URL
    private let timeout: TimeInterval
    private let retryIntervalMicroseconds: useconds_t

    public init(
        containerURL: URL,
        lockFileName: String = "app-integrity-delegated-grants.lock",
        timeout: TimeInterval = 0.25,
        retryInterval: TimeInterval = 0.005
    ) throws {
        guard containerURL.isFileURL,
              !lockFileName.isEmpty,
              lockFileName.utf8.count <= 120,
              lockFileName.unicodeScalars.allSatisfy({
                  switch $0.value {
                  case 45, 46, 48...57, 65...90, 95, 97...122:
                      true
                  default:
                      false
                  }
              }),
              timeout > 0,
              timeout <= 2,
              retryInterval > 0,
              retryInterval <= timeout else {
            throw AppIntegrityDelegatedGrantCoordinationError.invalidConfiguration
        }
        lockFileURL = containerURL.appendingPathComponent(
            lockFileName,
            isDirectory: false
        )
        self.timeout = timeout
        retryIntervalMicroseconds = useconds_t(retryInterval * 1_000_000)
    }

    public func withExclusiveAccess<Result>(
        _ operation: () throws -> Result
    ) throws -> Result {
        let descriptor = open(
            lockFileURL.path,
            O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW,
            S_IRUSR | S_IWUSR
        )
        guard descriptor >= 0 else {
            throw AppIntegrityDelegatedGrantCoordinationError.unavailable(errno)
        }
        defer { close(descriptor) }

        let deadline = Date().addingTimeInterval(timeout)
        while flock(descriptor, LOCK_EX | LOCK_NB) != 0 {
            let code = errno
            guard code == EWOULDBLOCK || code == EAGAIN else {
                throw AppIntegrityDelegatedGrantCoordinationError.unavailable(code)
            }
            guard Date() < deadline else {
                throw AppIntegrityDelegatedGrantCoordinationError.timedOut
            }
            usleep(retryIntervalMicroseconds)
        }
        defer { flock(descriptor, LOCK_UN) }
        return try operation()
    }
}
