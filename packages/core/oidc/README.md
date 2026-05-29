[Back to root](https://github.com/blissful-group/blissy)

# <img src="https://raw.githubusercontent.com/blissful-group/blissy/main/assets/blissy.png" alt="" width="28" />- [@blissy-auth/oidc](https://github.com/blissful-group/blissy/blob/main/packages/core/oidc)

![NPM License](https://img.shields.io/npm/l/@blissy-auth/oidc)
![NPM Unpacked Size](https://img.shields.io/npm/unpacked-size/@blissy-auth/oidc)

Minimal OpenID Connect protocol primitives for TypeScript built on top of `@blissy-auth/oauth2`, `@blissy-auth/jose`, platform APIs, and `effect`.

This package currently provides:

- `OIDCAuthorizationRequest` for authorization endpoint URL construction with the required `openid` scope
- `OIDCCallback` for authorization callback parsing
- `OIDCDiscovery` for provider discovery URLs and metadata parsing
- `OIDCIDToken` for ID token decoding, verification, and OIDC claim validation
- `OIDCNonce` for nonce generation and validation
- `OIDCUserInfo` for UserInfo response parsing

Every public operation returns an `Effect`, so callers can decide whether to run it with `Effect.runPromise`, compose it, or handle failures functionally.

## Dependencies

`@blissy-auth/oidc` keeps its dependency surface intentionally small.

- Runtime dependencies: `effect`
- No HTTP client dependency
- No OpenID Connect framework dependency

Request builders and parsers do not perform network IO. They construct and validate protocol values, letting the caller choose the HTTP client, retry policy, logging, credential handling, and session management.

## Install

```bash
pnpm add @blissy-auth/oidc effect
```

```bash
npm install @blissy-auth/oidc effect
```

## Runtime Requirements

- A runtime with `globalThis.crypto`
- `crypto.subtle` for JOSE verification through `@blissy-auth/jose`
- `TextEncoder` and `TextDecoder`

Node.js versions with Web Crypto support work out of the box.

OIDC uses the workspace crypto service indirectly through OAuth2, JOSE, and nonce generation. See [`@blissy-auth/crypto`](https://github.com/blissful-group/blissy/tree/main/services/crypto) for documentation on overriding the default Web Crypto-backed service in tests or custom runtimes.

## Current Support

This package intentionally implements focused OpenID Connect relying-party primitives today.

### Authorization Request

- Authorization code request URL construction
- Automatic `openid` scope inclusion
- `nonce`
- `state`
- PKCE parameters through `@blissy-auth/oauth2`

### Callback

- Query response mode through `@blissy-auth/oauth2`
- Successful callback parsing
- Authorization error callback parsing
- State validation

### Discovery

- Standard `/.well-known/openid-configuration` URL construction
- OpenID Provider Metadata parsing
- Required issuer, authorization endpoint, JWKS URI, response type, subject type, and ID token signing algorithm metadata validation

### ID Token

- Decode ID tokens without signature verification
- Verify ID tokens with a direct key or JWK Set through `@blissy-auth/jose`
- OIDC claim validation for `iss`, `sub`, `aud`, `exp`, `iat`, `nonce`, and `azp`

### Nonce

- Cryptographically random URL-safe nonce generation
- Configurable nonce byte length
- Nonce validation with constant-time string comparison

### UserInfo

- UserInfo response object parsing
- Required `sub` validation

## Not Implemented Yet

- Discovery document fetching
- JWKS document fetching
- Authorization code token exchange orchestration
- Session management
- Framework integration
- `form_post` and fragment response modes

## Basic Usage

```ts
import { Effect } from "effect";
import {
  OIDCAuthorizationRequest,
  OIDCCallback,
  OIDCDiscovery,
  OIDCIDToken,
  OIDCNonce,
  OIDCUserInfo,
} from "@blissy-auth/oidc";
```

## Discovery

```ts
import { Effect } from "effect";
import { OIDCDiscovery } from "@blissy-auth/oidc";

const url = await Effect.runPromise(
  OIDCDiscovery.configurationUrl("https://issuer.example"),
);

const metadata = await Effect.runPromise(
  OIDCDiscovery.parse({
    issuer: "https://issuer.example",
    authorization_endpoint: "https://issuer.example/authorize",
    jwks_uri: "https://issuer.example/jwks.json",
    response_types_supported: ["code"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
  }),
);
```

## Authorization Request

```ts
import { Effect } from "effect";
import { OIDCAuthorizationRequest, OIDCNonce } from "@blissy-auth/oidc";

const nonce = await Effect.runPromise(OIDCNonce.generate());

const url = await Effect.runPromise(
  OIDCAuthorizationRequest.authorizationCode({
    authorizationEndpoint: "https://issuer.example/authorize",
    clientId: "client-123",
    redirectUri: "https://client.example/callback",
    scope: ["profile", "email"],
    state: "state-123",
    nonce,
  }),
);
```

The `openid` scope is added automatically when missing.

## Callback

```ts
import { Effect } from "effect";
import { OIDCCallback } from "@blissy-auth/oidc";

const callback = await Effect.runPromise(
  OIDCCallback.authorizationCode({
    callbackUrl: "https://client.example/callback?code=code-123&state=state-123",
    expectedState: "state-123",
  }),
);
```

## ID Token

```ts
import { Effect } from "effect";
import { OIDCIDToken } from "@blissy-auth/oidc";

const decoded = await Effect.runPromise(
  OIDCIDToken.verify({
    token: idToken,
    issuer: "https://issuer.example",
    audience: "client-123",
    expectedNonce: nonce,
    jwks,
  }),
);
```

## UserInfo

```ts
import { Effect } from "effect";
import { OIDCUserInfo } from "@blissy-auth/oidc";

const userinfo = await Effect.runPromise(
  OIDCUserInfo.parse({
    sub: "user-123",
    email: "user@example.com",
  }),
);
```

## Non-goals

This package does not fetch discovery documents, fetch JWKS documents, exchange authorization codes, manage sessions, or integrate with a web framework. Those responsibilities are intentionally left to application code or future higher-level packages.
