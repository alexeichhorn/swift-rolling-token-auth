import Foundation
import Crypto

/// A generated rolling token together with the timestamp bucket it belongs to.
public struct RollingToken: Sendable, Equatable {
    /// Hex-encoded HMAC-SHA256 token value.
    public let token: String

    /// Time bucket (`unixTime / interval`) the token was generated for.
    public let timestamp: Int64

    /// Creates a token value with its corresponding timestamp bucket.
    public init(token: String, timestamp: Int64) {
        self.token = token
        self.timestamp = timestamp
    }

    /// Returns the token offset from a manager's current timestamp bucket.
    ///
    /// A value of `0` means current token, `-1` means previous bucket, `1` means next bucket.
    public func offset(in manager: RollingTokenManager) -> Int64 {
        timestamp - manager.currentTimestamp()
    }
}

/// Generates and validates rolling HMAC-SHA256 tokens with configurable clock tolerance.
///
/// Use this type when you need verification logic (typically server-side).
/// Validation uses an internal cache of active time buckets and is therefore mutating.
public struct RollingTokenManager: Sendable {
    private let secret: Data

    /// Size of each time bucket in seconds.
    public let interval: Int64

    /// Number of buckets accepted before and after the current bucket during validation.
    public let tolerance: Int64

    private var activeTokens: [RollingToken]
    private let nowProvider: @Sendable () -> TimeInterval

    /// Creates a manager from a UTF-8 secret string.
    ///
    /// - Parameters:
    ///   - secret: Shared secret used to compute HMAC-SHA256.
    ///   - interval: Bucket size in seconds. Must be greater than zero.
    ///   - tolerance: Accepted bucket window around "now". Must be zero or greater.
    public init(secret: String, interval: Int64, tolerance: Int64 = 1) {
        self.init(secret: Data(secret.utf8), interval: interval, tolerance: tolerance)
    }

    /// Creates a manager from raw secret bytes.
    ///
    /// - Parameters:
    ///   - secret: Shared secret bytes used to compute HMAC-SHA256.
    ///   - interval: Bucket size in seconds. Must be greater than zero.
    ///   - tolerance: Accepted bucket window around "now". Must be zero or greater.
    public init(secret: Data, interval: Int64, tolerance: Int64 = 1) {
        self.init(secret: secret, interval: interval, tolerance: tolerance, nowProvider: {
            Date().timeIntervalSince1970
        })
    }

    init(
        secret: Data,
        interval: Int64,
        tolerance: Int64 = 1,
        nowProvider: @escaping @Sendable () -> TimeInterval
    ) {
        precondition(interval > 0, "interval must be greater than zero")
        precondition(tolerance >= 0, "tolerance must not be negative")

        self.secret = secret
        self.interval = interval
        self.tolerance = tolerance
        self.activeTokens = []
        self.nowProvider = nowProvider
    }

    /// Returns the current timestamp bucket (`unixTime / interval`).
    public func currentTimestamp() -> Int64 {
        Int64(nowProvider()) / interval
    }

    /// Generates a token for the current bucket or a relative bucket offset.
    ///
    /// - Parameter offset: Relative bucket offset (`0` current, `-1` previous, `1` next).
    public func generateToken(offset: Int64 = 0) -> RollingToken {
        let timestamp = currentTimestamp() + offset
        return token(forTimestamp: timestamp)
    }

    /// Validates a token against the current tolerance window.
    ///
    /// This method is mutating because it refreshes the internal token cache.
    public mutating func isValid(_ token: String) -> Bool {
        refreshTokens()
        return activeTokens.contains { $0.token == token }
    }

    private func token(forTimestamp timestamp: Int64) -> RollingToken {
        let payload = Data(String(timestamp).utf8)
        let key = SymmetricKey(data: secret)
        let digest = HMAC<SHA256>.authenticationCode(for: payload, using: key)
        let token = digest.rollingTokenAuthHexEncodedString
        return RollingToken(token: token, timestamp: timestamp)
    }

    private mutating func refreshTokens() {
        let current = currentTimestamp()
        activeTokens.removeAll { abs($0.timestamp - current) > tolerance }

        if activeTokens.count == Int(1 + 2 * tolerance) {
            return
        }

        let existingTimestamps = Set(activeTokens.map(\.timestamp))
        for offset in (-tolerance)...tolerance {
            let timestamp = current + offset
            if existingTimestamps.contains(timestamp) {
                continue
            }

            activeTokens.append(token(forTimestamp: timestamp))
        }
    }
}

extension Sequence where Element == UInt8 {
    var rollingTokenAuthHexEncodedString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
