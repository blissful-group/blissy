---
"@blissy-auth/crypto": patch
"@blissy-auth/jose": patch
"@blissy-auth/oauth2": patch
"@blissy-auth/oidc": patch
---

Move the crypto package into the core workspace and make it publishable.
Standardize core package build and publish metadata for tsdown-generated package exports, and update internal imports to consume package root exports instead of source subpaths.
