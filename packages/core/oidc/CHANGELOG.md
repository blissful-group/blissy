# @blissy-auth/oidc

## 0.0.3

### Patch Changes

- b60f5c1: Move the crypto package into the core workspace and make it publishable.
  Standardize core package build and publish metadata for tsdown-generated package exports, and update internal imports to consume package root exports instead of source subpaths.
- Updated dependencies [b60f5c1]
- Updated dependencies [f3b256f]
  - @blissy-auth/crypto@0.0.2
  - @blissy-auth/jose@0.1.3
  - @blissy-auth/oauth2@0.0.4

## 0.0.2

### Patch Changes

- 3ce931a: Move core package sources under `packages/core`.
- 5d23827: Refactor OAuth2 and OIDC internals into module helper classes for more focused validation and helper testing.
- Updated dependencies [3ce931a]
- Updated dependencies [5d23827]
- Updated dependencies [5d23827]
  - @blissy-auth/jose@0.1.2
  - @blissy-auth/oauth2@0.0.3

## 0.0.1

### Patch Changes

- feb96d2: Add the initial OpenID Connect package with provider discovery metadata parsing, nonce primitives, authorization request helpers, callback parsing, ID token validation, UserInfo parsing, and package documentation.
