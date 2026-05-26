[Back to root](https://github.com/blissful-group/blissy/blob/main/README.md)

# <img src="https://raw.githubusercontent.com/blissful-group/blissy/main/assets/blissy.png" alt="" width="28" />- [@blissy-auth/oauth2](https://github.com/blissful-group/blissy/blob/main/packages/oauth2/README.md)

![NPM License](https://img.shields.io/npm/l/@blissy-auth/oauth2)
![npm package minimized gzipped size (scoped)](https://img.shields.io/bundlejs/size/@blissy-auth/oauth2)
![NPM Unpacked Size](https://img.shields.io/npm/unpacked-size/@blissy-auth/oauth2)

Minimal OAuth 2.0 protocol primitives for TypeScript built on top of platform APIs and `effect`.

This package currently provides:

- `OAuth2AuthorizationRequest` for authorization endpoint URL construction
- `OAuth2AuthorizationResponse` for authorization callback parsing
- `OAuth2ClientAuthentication` for public, `client_secret_basic`, and `client_secret_post` authentication fragments
- `OAuth2PKCE` for PKCE verifier generation, challenge creation, and challenge verification
- `OAuth2Scope` for scope parsing, formatting, and comparison
- `OAuth2State` for state generation and validation
- `OAuth2TokenRequest` for token endpoint request construction
- `OAuth2TokenResponse` for token success and token error response parsing
- `OAuth2Crypto` for Effect-based injection of randomness and hashing

Every public operation returns an `Effect`, so callers can decide whether to run it with `Effect.runPromise`, compose it, or handle failures functionally.

## Dependencies

`@blissy-auth/oauth2` keeps its dependency surface intentionally small.

- Runtime dependencies: `effect`
- No HTTP client dependency
- No OAuth framework dependency

Request builders do not perform network IO. They construct protocol values and let the caller choose the HTTP client, retry policy, logging, and credential handling.

## Install

```bash
pnpm add @blissy-auth/oauth2 effect
```

```bash
npm install @blissy-auth/oauth2 effect
```

## Runtime Requirements

- A runtime with `globalThis.crypto`
- `crypto.subtle` for PKCE S256 challenges
- `TextEncoder` and `TextDecoder`

Node.js versions with Web Crypto support work out of the box.

## Current Support

This package intentionally implements focused OAuth 2.0 primitives today.

### Authorization Request

- Authorization code request URL construction
- `response_type=code`
- `client_id`
- `redirect_uri`
- `scope`
- `state`
- `code_challenge`
- `code_challenge_method`
- Extension parameters with reserved parameter collision rejection

### Authorization Response

- Query response mode
- Successful callback parsing
- Authorization error callback parsing
- State validation
- Reserved response parameter duplicate rejection
- OAuth authorization error field validation

### PKCE

- Code verifier generation
- Code verifier validation
- Plain code challenge creation
- S256 code challenge creation
- Code challenge verification
- RFC 7636 S256 behavior

### State

- Cryptographically random URL-safe state generation
- Configurable state byte length
- State validation with constant-time string comparison

### Scope

- Scope parsing
- Scope formatting
- Duplicate normalization
- Inclusion checks
- Missing-scope calculation

### Client Authentication

- Public clients with no secret
- `client_secret_basic`
- `client_secret_post`
- OAuth form encoding for client credentials

### Token Request

- `authorization_code` grant request construction
- `refresh_token` grant request construction
- `client_credentials` grant request construction
- `application/x-www-form-urlencoded` request bodies
- POST method
- Client authentication fragments
- Extension parameters with reserved parameter collision rejection

### Token Response

- Successful access token responses
- `Bearer` token type validation and normalization
- `expires_in`
- `refresh_token`
- `scope`
- Token error responses
- `error_description`
- `error_uri`

### Effect Services

- `OAuth2Crypto` for randomness and hashing
- Defaults use platform Web Crypto
- Tests and callers can override the service with `Effect.provideService`

## Not Implemented Yet

- Redirect URI validation and registered redirect URI matching
- Token revocation
- Token introspection
- Fragment response mode parsing
- Shared HTTP response parsing utilities
- Shared OAuth error model beyond module-specific typed errors

## Basic Usage

```ts
import { Effect } from "effect";
import {
  OAuth2AuthorizationRequest,
  OAuth2AuthorizationResponse,
  OAuth2ClientAuthentication,
  OAuth2PKCE,
  OAuth2Scope,
  OAuth2State,
  OAuth2TokenRequest,
  OAuth2TokenResponse,
} from "@blissy-auth/oauth2";
```

## Authorization Code Flow

### Build An Authorization URL

Use `OAuth2AuthorizationRequest` to build the browser redirect URL.

```ts
import { Effect } from "effect";
import {
  OAuth2AuthorizationRequest,
  OAuth2PKCE,
  OAuth2State,
} from "@blissy-auth/oauth2";

const state = await Effect.runPromise(OAuth2State.generate());
const codeVerifier = await Effect.runPromise(OAuth2PKCE.generateCodeVerifier());
const codeChallenge = await Effect.runPromise(
  OAuth2PKCE.createCodeChallenge({ codeVerifier }),
);

const authorizationUrl = await Effect.runPromise(
  OAuth2AuthorizationRequest.authorizationCode({
    authorizationEndpoint: "https://authorization-server.example/authorize",
    clientId: "client-123",
    redirectUri: "https://client.example/callback",
    scope: ["openid", "profile"],
    state,
    codeChallenge,
    codeChallengeMethod: "S256",
  }),
);

window.location.assign(authorizationUrl.toString());
```

### Parse The Authorization Callback

Use `OAuth2AuthorizationResponse` after the authorization server redirects back to your application.

```ts
import { Effect } from "effect";
import { OAuth2AuthorizationResponse } from "@blissy-auth/oauth2";

const authorizationResponse = await Effect.runPromise(
  OAuth2AuthorizationResponse.parse({
    callbackUrl: "https://client.example/callback?code=code-123&state=state-123",
    expectedState: "state-123",
  }),
);

if (authorizationResponse.type === "success") {
  console.log(authorizationResponse.code);
}

if (authorizationResponse.type === "error") {
  console.log(authorizationResponse.error);
}
```

### Exchange The Authorization Code For Tokens

Use `OAuth2TokenRequest` to construct the token endpoint request. The request object is pure data and can be sent with `fetch`, your server framework, or any HTTP client.

```ts
import { Effect } from "effect";
import {
  OAuth2ClientAuthentication,
  OAuth2TokenRequest,
  OAuth2TokenResponse,
} from "@blissy-auth/oauth2";

const authentication = await Effect.runPromise(
  OAuth2ClientAuthentication.clientSecretBasic({
    clientId: "client-123",
    clientSecret: "secret-123",
  }),
);

const request = await Effect.runPromise(
  OAuth2TokenRequest.authorizationCode({
    authentication,
    code: "code-123",
    codeVerifier: "stored-code-verifier",
    redirectUri: "https://client.example/callback",
    tokenEndpoint: "https://authorization-server.example/token",
  }),
);

const httpResponse = await fetch(request.url, {
  method: request.method,
  headers: request.headers,
  body: request.body,
});

const tokenResponse = await Effect.runPromise(
  OAuth2TokenResponse.parse(await httpResponse.json()),
);

if (tokenResponse.type === "success") {
  console.log(tokenResponse.accessToken);
}
```

## PKCE

Generate and validate PKCE inputs.

```ts
import { Effect } from "effect";
import { OAuth2PKCE } from "@blissy-auth/oauth2";

const codeVerifier = await Effect.runPromise(OAuth2PKCE.generateCodeVerifier());
const codeChallenge = await Effect.runPromise(
  OAuth2PKCE.createCodeChallenge({
    codeVerifier,
    method: "S256",
  }),
);

await Effect.runPromise(
  OAuth2PKCE.verifyCodeChallenge({
    codeChallenge,
    codeVerifier,
    method: "S256",
  }),
);
```

Available attached types and errors:

- `OAuth2PKCE.CodeChallengeMethod`
- `OAuth2PKCE.CodeVerifierGenerationOptions`
- `OAuth2PKCE.CodeVerifierValidationError`
- `OAuth2PKCE.CodeChallengeMethodError`
- `OAuth2PKCE.CodeChallengeVerificationError`

## State

Generate state values and validate returned state.

```ts
import { Effect } from "effect";
import { OAuth2State } from "@blissy-auth/oauth2";

const state = await Effect.runPromise(OAuth2State.generate());

await Effect.runPromise(
  OAuth2State.validate({
    expectedState: state,
    returnedState: state,
  }),
);
```

Available attached types and errors:

- `OAuth2State.ValidationOptions`
- `OAuth2State.GenerationError`
- `OAuth2State.ValidationError`

## Scope

Parse, format, and compare OAuth scopes.

```ts
import { Effect } from "effect";
import { OAuth2Scope } from "@blissy-auth/oauth2";

const scopes = await Effect.runPromise(OAuth2Scope.parse("read write read"));
const formatted = await Effect.runPromise(OAuth2Scope.format(scopes));
const includesRead = await Effect.runPromise(
  OAuth2Scope.includes(scopes, "read"),
);
```

Available attached types and errors:

- `OAuth2Scope.Value`
- `OAuth2Scope.Set`
- `OAuth2Scope.ValidationError`

## Client Authentication

Build reusable client authentication fragments for token endpoint requests.

```ts
import { Effect } from "effect";
import { OAuth2ClientAuthentication } from "@blissy-auth/oauth2";

const basic = await Effect.runPromise(
  OAuth2ClientAuthentication.clientSecretBasic({
    clientId: "client-123",
    clientSecret: "secret-123",
  }),
);

const post = await Effect.runPromise(
  OAuth2ClientAuthentication.clientSecretPost({
    clientId: "client-123",
    clientSecret: "secret-123",
  }),
);
```

Available attached errors:

- `OAuth2ClientAuthentication.Error`

## Token Requests

Build token endpoint request objects without network IO.

```ts
import { Effect } from "effect";
import { OAuth2TokenRequest } from "@blissy-auth/oauth2";

const refreshRequest = await Effect.runPromise(
  OAuth2TokenRequest.refreshToken({
    refreshToken: "refresh-123",
    scope: ["read"],
    tokenEndpoint: "https://authorization-server.example/token",
  }),
);

const clientCredentialsRequest = await Effect.runPromise(
  OAuth2TokenRequest.clientCredentials({
    scope: ["read"],
    tokenEndpoint: "https://authorization-server.example/token",
  }),
);
```

Available attached types and errors:

- `OAuth2TokenRequest.Authentication`
- `OAuth2TokenRequest.ExtensionParameters`
- `OAuth2TokenRequest.Request`
- `OAuth2TokenRequest.ValidationError`

## Token Responses

Parse token endpoint JSON responses.

```ts
import { Effect } from "effect";
import { OAuth2TokenResponse } from "@blissy-auth/oauth2";

const response = await Effect.runPromise(
  OAuth2TokenResponse.parse({
    access_token: "access-123",
    token_type: "Bearer",
    expires_in: 3600,
    refresh_token: "refresh-123",
    scope: "read write",
  }),
);

if (response.type === "success") {
  console.log(response.accessToken);
}
```

Available attached types and errors:

- `OAuth2TokenResponse.Value`
- `OAuth2TokenResponse.Success`
- `OAuth2TokenResponse.Error`
- `OAuth2TokenResponse.ValidationError`

## Effect Dependency Injection

`OAuth2Crypto` is an Effect service with default implementations backed by Web Crypto. You can override it with `Effect.provideService` for deterministic tests or custom runtime integrations.

```ts
import { Effect } from "effect";
import { OAuth2Crypto, OAuth2State } from "@blissy-auth/oauth2";

const state = await Effect.runPromise(
  OAuth2State.generate(4).pipe(
    Effect.provideService(OAuth2Crypto, {
      digest: globalThis.crypto.subtle.digest.bind(globalThis.crypto.subtle),
      randomValues: (bytes) => {
        bytes.set([0xff, 0xee, 0xdd, 0xcc]);

        return bytes;
      },
    }),
  ),
);
```

Available attached types:

- `OAuth2Crypto.Service`

## Security Notes

- Do not log client secrets, token values, authorization headers, or full request objects containing credentials.
- Validation errors avoid embedding client secrets and authorization headers.
- Request builders do not perform network IO, which keeps credential transport under caller control.
- PKCE and state generation use Web Crypto by default through `OAuth2Crypto`.

## Development

Run package tasks with Moon from the repository root.

```sh
moon run oauth2:format
moon run oauth2:lint
moon run oauth2:test
moon run oauth2:build
```

The test suite is expected to maintain full statement, branch, function, and line coverage.

## License

MIT
