# @blissy-auth/crypto

## 0.0.2

### Patch Changes

- b60f5c1: Move the crypto package into the core workspace and make it publishable.
  Standardize core package build and publish metadata for tsdown-generated package exports, and update internal imports to consume package root exports instead of source subpaths.
- f3b256f: Add OAuth2 token introspection and revocation primitives.
  Inline local public types into their owning modules and infer schema-backed types from Effect schemas, removing standalone `.types.ts` files.

## 0.0.1

### Patch Changes

- 7a1ebd9: Use shared injectable crypto and algorithm services for Web Crypto operations.
- efc8768: Move the OAuth2 crypto service to a shared private workspace package.
