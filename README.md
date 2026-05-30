# <img src="https://raw.githubusercontent.com/blissful-group/blissy/main/assets/blissy.png" alt="" height="28" />- [Blissy](https://github.com/blissful-group/blissy)

![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/blissful-group/blissy/main.yml)
[![codecov](https://codecov.io/gh/blissful-group/blissy/graph/badge.svg?token=JQFUkDtwcb)](https://codecov.io/gh/blissful-group/blissy)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/blissful89)](https://github.com/Blissful89)

The simple auth library.

## Repository

Monorepository for the `@blissy-auth` authentication packages.

This repository contains the packages and shared code used to build auth for the `@blissy-auth` ecosystem.

## Dependencies

The packages in this repository aim to keep dependencies intentionally small.

- Core runtime dependency: `effect`
- Platform primitives where possible, such as Web Crypto
- No large auth or JOSE dependency stacks

To view the dependency graph run `moon pg`

## Packages

- [`@blissy-auth/crypto`](./packages/core/crypto/README.md): Shared Effect crypto service used by workspace packages
- [`@blissy-auth/jose`](./packages/core/jose/README.md): JOSE primitives for `JWA`, `JWE`, `JWK`, `JWKS`, `JWS`, and `JWT`
- [`@blissy-auth/oauth2`](./packages/core/oauth2/README.md): OAuth 2.0 primitives for authorization requests, authorization responses, PKCE, state, scopes, client authentication, token requests, token responses, token introspection, and token revocation
- [`@blissy-auth/oidc`](./packages/core/oidc/README.md): OpenID Connect primitives for authorization requests, callbacks, discovery, ID token validation, nonce handling, and UserInfo parsing

## Getting Started

Install `proto` by following the official documentation:

https://moonrepo.dev/docs/proto/install

Then install the repository's managed tools:

```sh
proto install
```
