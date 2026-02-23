import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import Testing
@testable import RollingTokenAuth

@Test("RollingTokenManager generates expected HMAC for fixed timestamp")
func generateTokenProducesExpectedDigest() {
    let manager = RollingTokenManager(
        secret: Data("test_secret".utf8),
        interval: 30,
        tolerance: 1,
        nowProvider: { TimeInterval(30 * 42) }
    )

    let token = manager.generateToken()
    #expect(token.timestamp == 42)
    #expect(token.token == "a57ddc684dcb4e1589fa24d6fee66e83b2323ce788b7f137e55ea53b691cd78c")

    let nextManager = RollingTokenManager(
        secret: Data("test_secret".utf8),
        interval: 30,
        tolerance: 1,
        nowProvider: { TimeInterval(30 * 43) }
    )
    let nextToken = nextManager.generateToken()
    #expect(nextToken.timestamp == 43)
    #expect(nextToken.token != token.token)
}

@Test("RollingTokenManager validates tokens within tolerance")
func validateTokensInsideTolerance() {
    var manager = RollingTokenManager(
        secret: Data("test_secret".utf8),
        interval: 30,
        tolerance: 1,
        nowProvider: { TimeInterval(30 * 100) }
    )

    let currentToken = manager.generateToken()
    let previousToken = manager.generateToken(offset: -1)
    let nextToken = manager.generateToken(offset: 1)
    let outOfRangeToken = manager.generateToken(offset: 2)

    let currentTokenIsValid = manager.isValid(currentToken.token)
    #expect(currentTokenIsValid)

    let previousTokenIsValid = manager.isValid(previousToken.token)
    #expect(previousTokenIsValid)

    let nextTokenIsValid = manager.isValid(nextToken.token)
    #expect(nextTokenIsValid)

    let outOfRangeTokenIsValid = manager.isValid(outOfRangeToken.token)
    #expect(outOfRangeTokenIsValid == false)

    var nextWindowManager = RollingTokenManager(
        secret: Data("test_secret".utf8),
        interval: 30,
        tolerance: 1,
        nowProvider: { TimeInterval(30 * 101) }
    )

    let nextTokenStillValid = nextWindowManager.isValid(nextToken.token)
    #expect(nextTokenStillValid)

    let previousTokenExpired = nextWindowManager.isValid(previousToken.token)
    #expect(previousTokenExpired == false)
}

@Test("RollingAuthorizationToken matches manager output at same timestamp")
func authorizationTokenMatchesManager() {
    let fixedNow = TimeInterval(30 * 7)
    let authToken = RollingAuthorizationToken(
        secret: Data("secret".utf8),
        interval: 30,
        nowProvider: { fixedNow }
    )
    let manager = RollingTokenManager(
        secret: Data("secret".utf8),
        interval: 30,
        tolerance: 1,
        nowProvider: { fixedNow }
    )

    #expect(authToken.generate() == manager.generateToken().token)
    #expect(authToken.generate(forTimestamp: 42) == manager.generateToken(offset: 35).token)
}

@Test("URLRequest authorization helper adds bearer header")
func urlRequestHelperAddsAuthorizationHeader() throws {
    let fixedNow = TimeInterval(30 * 5)
    let auth = RollingAuthorizationToken(
        secret: Data("secret".utf8),
        interval: 30,
        nowProvider: { fixedNow }
    )

    var request = URLRequest(url: try #require(URL(string: "https://example.com")))
    request.addAuthentication(with: auth)

    let expectedHeader = "Bearer \(auth.generate())"
    #expect(request.value(forHTTPHeaderField: "Authorization") == expectedHeader)
}
