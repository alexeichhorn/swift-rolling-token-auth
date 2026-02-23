import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import Crypto

public struct RollingToken: Sendable, Equatable {
    public let token: String
    public let timestamp: Int64

    public init(token: String, timestamp: Int64) {
        self.token = token
        self.timestamp = timestamp
    }

    public func offset(in manager: RollingTokenManager) -> Int64 {
        timestamp - manager.currentTimestamp()
    }
}

public struct RollingTokenManager: Sendable {
    private let secret: Data
    public let interval: Int64
    public let tolerance: Int64
    private var activeTokens: [RollingToken]
    private let nowProvider: @Sendable () -> TimeInterval

    public init(secret: String, interval: Int64, tolerance: Int64 = 1) {
        self.init(secret: Data(secret.utf8), interval: interval, tolerance: tolerance)
    }

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

    public func currentTimestamp() -> Int64 {
        Int64(nowProvider()) / interval
    }

    public func generateToken(offset: Int64 = 0) -> RollingToken {
        let timestamp = currentTimestamp() + offset
        return token(forTimestamp: timestamp)
    }

    public mutating func isValid(_ token: String) -> Bool {
        refreshTokens()
        return activeTokens.contains { $0.token == token }
    }

    private func token(forTimestamp timestamp: Int64) -> RollingToken {
        let payload = Data(String(timestamp).utf8)
        let key = SymmetricKey(data: secret)
        let digest = HMAC<SHA256>.authenticationCode(for: payload, using: key)
        let token = digest.hexEncodedString
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

public struct RollingAuthorizationToken: Sendable {
    private let secret: Data
    public let interval: Int64
    private let nowProvider: @Sendable () -> TimeInterval

    public init(secret: String, interval: Int64) {
        self.init(secret: Data(secret.utf8), interval: interval)
    }

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

    public func generate(forTimestamp timestamp: Int64) -> String {
        let payload = Data(String(timestamp).utf8)
        let key = SymmetricKey(data: secret)
        let digest = HMAC<SHA256>.authenticationCode(for: payload, using: key)
        return digest.hexEncodedString
    }

    public func generate() -> String {
        let timestamp = Int64(nowProvider()) / interval
        return generate(forTimestamp: timestamp)
    }
}

public extension URLRequest {
    mutating func addBearerToken(_ token: String) {
        setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
    }

    mutating func addAuthentication(with token: RollingAuthorizationToken) {
        addBearerToken(token.generate())
    }

    mutating func addAuthentication(with manager: RollingTokenManager, offset: Int64 = 0) {
        addBearerToken(manager.generateToken(offset: offset).token)
    }

    init(url: URL, authentication token: RollingAuthorizationToken) {
        self.init(url: url)
        addAuthentication(with: token)
    }

    init(url: URL, authentication token: RollingAuthorizationToken, timeoutInterval: TimeInterval) {
        self.init(url: url, timeoutInterval: timeoutInterval)
        addAuthentication(with: token)
    }
}

private extension Sequence where Element == UInt8 {
    var hexEncodedString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
