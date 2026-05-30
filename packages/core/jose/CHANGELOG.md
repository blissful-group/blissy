# @blissy-auth/jose

## 0.1.3

### Patch Changes

- b60f5c1: Move the crypto package into the core workspace and make it publishable.
  Standardize core package build and publish metadata for tsdown-generated package exports, and update internal imports to consume package root exports instead of source subpaths.
- f3b256f: Add OAuth2 token introspection and revocation primitives.
  Inline local public types into their owning modules and infer schema-backed types from Effect schemas, removing standalone `.types.ts` files.
- Updated dependencies [b60f5c1]
- Updated dependencies [f3b256f]
  - @blissy-auth/crypto@0.0.2

## 0.1.2

### Patch Changes

- 3ce931a: Move core package sources under `packages/core`.
- 5d23827: Refactor JOSE internals into module helper classes for more focused validation and helper testing.

## 0.1.1

### Patch Changes

- 11de32a: Package name typo in documentation

## 0.1.0

### Minor Changes

- 64bcb0e: Add RS256 and ES256 JWT verification support with JWK Set key resolution.

### Patch Changes

- 7a1ebd9: Use shared injectable crypto and algorithm services for Web Crypto operations.
- Updated dependencies [7a1ebd9]
- Updated dependencies [efc8768]
  - @blissy-auth/crypto@0.0.1

## 0.0.6

### Patch Changes

- d91ce09: Refactor updates and cleanup

## 0.0.5

### Patch Changes

- e726038: Update package.json with correct source exports for internal workspace usage

## 0.0.4

### Patch Changes

- d887fb3: Add codecov report uploading

## 0.0.3

### Patch Changes

- 161e927: Add keywords

## 0.0.2

### Patch Changes

- 6bfe970: A forced release with just package release scripting updates

## 0.0.1

### Patch Changes

- 1b6ebd0: Initial beta release of package
