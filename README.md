# RollingTokenAuth

Rolling token authentication for Swift clients and servers.

## Features

- HMAC-SHA256 rolling token generation
- Tolerance window validation (`past/current/future` intervals)
- `URLRequest` helpers for bearer auth headers

## Installation

```swift
dependencies: [
    .package(url: "https://github.com/alexeichhorn/swift-rolling-token-auth.git", from: "0.1.0")
]
```

## Usage

## Two Variants

This package provides two public token types for different use-cases:

- `RollingTokenManager`
  - Full generator + validator.
  - Use this when you need `tolerance`-based token validation (typically server-side).
- `RollingAuthorizationToken`
  - Lightweight generator-only helper.
  - Use this when you only need to attach outbound bearer tokens (typically client-side).

### `RollingTokenManager` (generation + validation)

```swift
import RollingTokenAuth

var manager = RollingTokenManager(secret: "my_secret", interval: 3600, tolerance: 1)
let token = manager.generateToken()

let isValid = manager.isValid(token.token)
```

With `tolerance: 1`, previous, current, and next interval tokens are accepted.

### `RollingAuthorizationToken` (generation only)

```swift
import Foundation
import RollingTokenAuth

let auth = RollingAuthorizationToken(secret: "my_secret", interval: 3600)
var request = URLRequest(url: URL(string: "https://example.com")!)
request.addAuthentication(with: auth)
```

You can also use `RollingTokenManager` directly for request auth:

```swift
import Foundation
import RollingTokenAuth

let manager = RollingTokenManager(secret: "my_secret", interval: 3600, tolerance: 1)
var request = URLRequest(url: URL(string: "https://example.com")!)
request.addAuthentication(with: manager)
```
