import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import Crypto

/// Lightweight rolling token generator for request authorization headers.
///
/// Use this type when you only need to generate outbound tokens (typically client-side),
/// without tolerance-based validation.
public struct RollingAuthorizationToken: Sendable {
    private let secret: Data

    /// Size of each time bucket in seconds.
    public let interval: Int64

    private let nowProvider: @Sendable () -> TimeInterval

    /// Creates a generator from a UTF-8 secret string.
    ///
    /// - Parameters:
    ///   - secret: Shared secret used to compute HMAC-SHA256.
    ///   - interval: Bucket size in seconds. Must be greater than zero.
    public init(secret: String, interval: Int64) {
        self.init(secret: Data(secret.utf8), interval: interval)
    }

    /// Creates a generator from raw secret bytes.
    ///
    /// - Parameters:
    ///   - secret: Shared secret bytes used to compute HMAC-SHA256.
    ///   - interval: Bucket size in seconds. Must be greater than zero.
    public init(secret: Data, interval: Int64) {
        self.init(secret: secret, interval: interval, nowProvider: {
            Date().timeIntervalSince1970
        })
    }

    init(secret: Data, interval: Int64, nowProvider: @escaping @Sendable () -> TimeInterval) {
        precondition(interval > 0, "interval must be greater than zero")
        self.secret = secret
        self.interval = interval
        self.nowProvider = nowProvider
    }

    /// Generates a token for a specific timestamp bucket.
    public func generate(forTimestamp timestamp: Int64) -> String {
        let payload = Data(String(timestamp).utf8)
        let key = SymmetricKey(data: secret)
        let digest = HMAC<SHA256>.authenticationCode(for: payload, using: key)
        return digest.rollingTokenAuthHexEncodedString
    }

    /// Generates a token for the current timestamp bucket.
    public func generate() -> String {
        let timestamp = Int64(nowProvider()) / interval
        return generate(forTimestamp: timestamp)
    }
}

public extension URLRequest {
    /// Sets the `Authorization` header to `Bearer <token>`.
    mutating func addBearerToken(_ token: String) {
        setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
    }

    /// Generates and applies a bearer token using `RollingAuthorizationToken`.
    mutating func addAuthentication(with token: RollingAuthorizationToken) {
        addBearerToken(token.generate())
    }

    /// Generates and applies a bearer token using `RollingTokenManager`.
    ///
    /// - Parameter offset: Relative bucket offset used when generating the token.
    mutating func addAuthentication(with manager: RollingTokenManager, offset: Int64 = 0) {
        addBearerToken(manager.generateToken(offset: offset).token)
    }

    /// Creates a request and immediately applies authorization via `RollingAuthorizationToken`.
    init(url: URL, authentication token: RollingAuthorizationToken) {
        self.init(url: url)
        addAuthentication(with: token)
    }

    /// Creates a request with custom timeout and applies authorization via `RollingAuthorizationToken`.
    init(url: URL, authentication token: RollingAuthorizationToken, timeoutInterval: TimeInterval) {
        self.init(url: url, timeoutInterval: timeoutInterval)
        addAuthentication(with: token)
    }
}
