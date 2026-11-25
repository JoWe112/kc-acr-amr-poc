# Security Policy

## Scope

This repository is a **local proof of concept**. The generated certificates, the realm's test
user/password, the `poc-api` client secret and the Keycloak admin credentials are intentionally
public test values and must never be used outside a local developer machine.

Security issues that are in scope:

- the `X509IssuerLoaAuthenticator` SPI (e.g. a way to obtain a higher `acr` than the issuing CA allows,
  bypassing the fail-closed policy, or header injection in proxy mode);
- the documented configuration patterns in `docs/` if following them leads to an insecure deployment.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private vulnerability reporting
(*Security → Report a vulnerability*) on this repository. Include the Keycloak version, the SPI version
and steps to reproduce. You can expect an initial response within 5 working days.

## Supported versions

| Version | Keycloak | Supported |
|---------|----------|-----------|
| 0.1.x   | 26.6.x   | ✅        |
