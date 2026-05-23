# <img src="https://raw.githubusercontent.com/blissful-group/blissy/main/assets/blissy.png" alt="" height="28" />[Blissy](https://github.com/blissful-group/blissy)

The simple auth library.

## Repository

Monorepository for the `@blissy-auth` authentication packages.

This repository contains the packages and shared code used to build auth for the `@blissy-auth` ecosystem.

## Dependencies

The packages in this repository aim to keep dependencies intentionally small.

- Core runtime dependency: `effect`
- Platform primitives where possible, such as Web Crypto
- No large auth or JOSE dependency stacks

## Packages

- [`@blissy-auth/jose`](./packages/jose/README.md): JOSE primitives for `JWA`, `JWE`, `JWK`, `JWKS`, `JWS`, and `JWT`

## Getting Started

Install `proto` by following the official documentation:

https://moonrepo.dev/docs/proto/install

Then install the repository's managed tools:

```sh
proto install
```
