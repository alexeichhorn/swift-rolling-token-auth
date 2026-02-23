# RollingTokenAuth

A simple rolling token authentication package for Swift clients and servers.
It generates time-based HMAC-SHA256 tokens and can validate them with clock tolerance.

## Features

- HMAC-SHA256 rolling token generation
- Tolerance window validation (`past/current/future` intervals)
- `URLRequest` helpers for bearer auth headers

## What Is Rolling Token Auth?

Rolling token auth is a shared-secret authentication scheme where tokens change automatically over time.

Instead of issuing a long-lived static token, both sides independently generate the same short-lived token from:

- A shared `secret`
- The same `interval` (for example, 3600 seconds)
- The current time bucket (`unixTimestamp / interval`)

Because both sides can compute the same token for "now", no token storage is required.

## How It Works

1. Convert current time to a time bucket (`timestamp = now / interval`).
2. Compute `HMAC_SHA256(secret, String(timestamp))`.
3. Hex-encode the digest and send it as bearer token.
4. On verification, accept tokens from current bucket and optionally nearby buckets (`tolerance`) to handle small clock drift.

## Installation

```swift
dependencies: [
    .package(url: "https://github.com/alexeichhorn/swift-rolling-token-auth.git", from: "0.1.0")
]
```

## Usage

This package provides two public token types for different use-cases.

### `RollingTokenManager` (generation + validation)

Use this when you need `tolerance`-based validation (typically server-side).

```swift
import RollingTokenAuth

var manager = RollingTokenManager(secret: "my_secret", interval: 3600, tolerance: 1)
let token = manager.generateToken()

let isValid = manager.isValid(token.token)
```

Parameters:

- `secret`: Shared key used for HMAC.
- `interval`: Token window in seconds. Smaller interval = shorter token lifetime.
- `tolerance`: Number of previous/next windows to accept during validation.

With `tolerance: 1`, these are valid:

- Previous interval token
- Current interval token
- Next interval token

### `RollingAuthorizationToken` (generation only)

Use this when you only need to generate outbound auth headers (typically client-side).

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

## When To Use This

Good fit:

- Service-to-service requests where both sides share a secret
- Lightweight auth where JWT/session infrastructure is unnecessary
- Cross-platform client/server codebases with matching rolling-token behavior

Less ideal:

- User identity/authorization systems that need claims, revocation, or rich session state
