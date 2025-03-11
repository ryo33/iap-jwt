# Changelog

## [0.2.0] - 2025-03-11

Security improvements

### Added

- `Error::TokenLifetimeTooLong` variant to indicate tokens with excessively long validity periods

### Changed

- Relaxes `iat` (issued at) claim validation to consider time skew
- Adds validation to ensure tokens follow Google IAP's recommended maximum lifetime (10 minutes + 2 * skew)
