# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-11-25

### Added
- `X509IssuerLoaAuthenticator` SPI for Keycloak 26.6: sets the Level of Authentication (`acr`) from the
  client certificate's Issuer DN via a configurable `<Issuer DN>::<level>` mapping, stores the issuer in the
  `x509_issuer_dn` user session note, fail-closed (or default LoA) for unknown CAs, and persists the LoA map
  to the user session for SSO/step-up. Also enforces an *essential* `acr` request on the X.509 path, where no
  Level-of-Authentication condition runs.
- Unit tests for the mapping and configuration parsing (29 tests).
- Realm `acr-poc` with ACR-to-LoA mapping (`loa1..loa3`), the `browser-acr-amr` flow (Cookie | X.509 |
  Passkey | Password), `acr`/`amr`/`x509_issuer` mappers, test client `bruno`, resource server `poc-api`
  and test user `testuser`.
- Docker Compose environment with direct mTLS in Keycloak and a static OAuth2 callback page.
- `scripts/generate-certs.sh` (three test CAs, server cert, client certs as `.p12`/`.pem`, truststore).
- End-to-end tests (`scripts/run-e2e.sh`, 16 scenarios) covering password, both CAs, unmapped CA, SSO,
  step-up, essential/voluntary `acr` (incl. essential `loa3` vs Standard/High Trust certificates), and passkey
  via a software authenticator.
- Bruno collection with PKCE login builders, token exchange with JWT decoding and claim tests, UserInfo and
  introspection; validated with Bruno CLI in both Safe and Developer sandbox (`scripts/validate-bruno.sh`).
- Swedish documentation: `docs/admin-guide.md` and `docs/app-owner-guide.md`.
