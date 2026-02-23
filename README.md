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

```swift
import RollingTokenAuth

var manager = RollingTokenManager(secret: "my_secret", interval: 3600, tolerance: 1)
let token = manager.generateToken()

let isValid = manager.isValid(token.token)
```

With `tolerance: 1`, previous, current, and next interval tokens are accepted.

### URLRequest helper

```swift
import Foundation
import RollingTokenAuth

let auth = RollingAuthorizationToken(secret: "my_secret", interval: 3600)
var request = URLRequest(url: URL(string: "https://example.com")!)
request.addAuthentication(with: auth)
```
