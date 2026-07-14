import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

public actor URLSessionAppIntegrityTransport: AppIntegrityTransport {
    private struct ChallengeRequest: Encodable {
        let applicationID: String
        let purpose: AppIntegrityChallengePurpose
    }

    private struct ServerErrorBody: Decodable {
        let code: String?
    }

    private let baseURL: URL
    private let session: URLSession

    public init(baseURL: URL, session: URLSession? = nil) {
        self.baseURL = baseURL
        if let session {
            self.session = session
        } else {
            let configuration = URLSessionConfiguration.ephemeral
            configuration.urlCache = nil
            configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
            configuration.httpCookieStorage = nil
            configuration.httpShouldSetCookies = false
            self.session = URLSession(configuration: configuration)
        }
    }

    public func requestChallenge(
        applicationID: String,
        purpose: AppIntegrityChallengePurpose
    ) async throws -> AppIntegrityChallenge {
        try await send(
            path: "v1/integrity/challenges",
            body: ChallengeRequest(applicationID: applicationID, purpose: purpose),
            response: AppIntegrityChallenge.self
        )
    }

    public func registerAttestation(
        _ request: AppIntegrityAttestationRequest
    ) async throws -> AppIntegrityAttestationResponse {
        try await send(
            path: "v1/integrity/attestations",
            body: request,
            response: AppIntegrityAttestationResponse.self
        )
    }

    public func establishSession(
        _ request: AppIntegritySessionRequest
    ) async throws -> AppIntegritySessionResponse {
        try await send(
            path: "v1/integrity/sessions",
            body: request,
            response: AppIntegritySessionResponse.self
        )
    }

    private func send<Body: Encodable, Response: Decodable>(
        path: String,
        body: Body,
        response: Response.Type
    ) async throws -> Response {
        var request = URLRequest(url: endpoint(path))
        request.httpMethod = "POST"
        request.timeoutInterval = 20
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .iso8601
        request.httpBody = try encoder.encode(body)

        let (data, urlResponse) = try await session.data(for: request)
        guard let httpResponse = urlResponse as? HTTPURLResponse else {
            throw AppIntegrityError.invalidServerResponse
        }
        guard 200..<300 ~= httpResponse.statusCode else {
            let code = try? JSONDecoder().decode(ServerErrorBody.self, from: data).code
            throw AppIntegrityError.transportFailure(
                statusCode: httpResponse.statusCode,
                code: code
            )
        }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        do {
            return try decoder.decode(response, from: data)
        } catch {
            throw AppIntegrityError.invalidServerResponse
        }
    }

    private func endpoint(_ path: String) -> URL {
        path.split(separator: "/").reduce(baseURL) { partial, component in
            partial.appendingPathComponent(String(component), isDirectory: false)
        }
    }
}
