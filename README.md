# IAP JWT

[![GitHub](https://img.shields.io/badge/GitHub-ryo33/iap__jwt-222222)](https://github.com/ryo33/iap-jwt)
![MIT/Apache 2.0](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)
[![Crates.io](https://img.shields.io/crates/v/iap_jwt)](https://crates.io/crates/iap_jwt)
[![docs.rs](https://img.shields.io/docsrs/iap_jwt)](https://docs.rs/iap_jwt)

Validate and decode Google Cloud Identity-Aware Proxy (IAP) JWTs

## Features

- Validate and decode JWTs issued by Google IAP <https://cloud.google.com/iap/docs/signed-headers-howto>
- Verify JWT signature using public keys from Google retrieved from the JWKS endpoint
- Validate standard claims like `exp`, `iat`, `aud`, `iss`
- Validate Google-specific claims like `hd` (hosted domain) and access levels
- Injectable public key retrieval and caching for testability
- Customizable validation options

## Usage

```sh
cargo add iap-jwt
```

```rust
use iap_jwt::{ValidationConfig};

let token = "..."; // JWT token from IAP

// reqwest Client implements iap_jwt::PublicKeySource with `reqwest` feature enabled (enabled by default)
let client = reqwest::Client::new();

let config = ValidationConfig::new(["/projects/1234567890/global/backendServices/test-service-id"])
    .with_google_hosted_domain(["example.com"])
    .with_access_levels(["ADMIN"]);

let claims = config.decode_and_validate(token, &client).await?;

println!("Authenticated user: {}", claims.sub);
```

## License

This project is licensed under either of the following licenses, at your option:

- Apache-2.0
- MIT
