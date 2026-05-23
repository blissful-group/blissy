[Back to root](https://github.com/blissful-group/blissy/blob/main/README.md)

# <img src="https://raw.githubusercontent.com/blissful-group/blissy/main/assets/blissy.png" alt="" width="28" /> [@blissy-auth/jose](https://github.com/blissful-group/blissy/blob/main/packages/jose/README.md)

Minimal JOSE primitives for TypeScript built on top of Web Crypto and `effect`.

This package currently provides:

- `JWA` for signing and verifying raw payloads
- `JWS` for compact, flattened, and general JSON signatures
- `JWE` for compact, flattened, and general JSON encryption
- `JWT` for signing, decoding, and verifying tokens
- `JWK` for parsing and filtering JWK Sets
- `JWKS` for parsing and filtering JWKS documents

Every public API returns an `Effect`, so callers can decide whether to run it with `Effect.runPromise`, compose it, or handle failures functionally.

## Dependencies

`@blissy/jose` keeps its dependency surface intentionally small.

- Runtime dependencies: `effect`
- No other runtime dependencies
- No crypto wrapper libraries
- No JOSE helper libraries

The implementation relies on platform Web Crypto APIs and `effect`, rather than pulling in a larger stack of transitive packages.

## Install

```bash
pnpm add @blissy/jose effect
```

## Runtime Requirements

- A runtime with `crypto.subtle`
- `TextEncoder` and `TextDecoder`

Node.js versions with Web Crypto support work out of the box.

## Current Support

This package intentionally implements a small supported subset today.

### JWA

- `HS256`
- `RS256`
- `ES256`

### JWS

- Compact serialization
- Flattened JSON serialization
- General JSON serialization
- `HS256`

### JWE

- `alg: "dir"`
- `enc: "A256GCM"`
- Compact serialization
- Flattened JSON serialization
- General JSON serialization

### JWT

- Signed JWTs with `HS256`
- Unsecured JWTs with `alg: "none"` only when explicitly allowed during verification
- Claim validation for `iss`, `sub`, `aud`, `exp`, `nbf`, and `iat`

### JWK / JWKS

- Parsing documents with a `keys` array
- Filtering by `kid`, `alg`, `kty`, and `use`
- Rejecting ambiguous matches

## Basic Usage

```ts
import { Effect } from "effect";
import { JWE, JWK, JWKS, JWA, JWS, JWT } from "@blissy-auth/jose";
```

## JWA

Use `JWA` when you want to sign or verify raw bytes directly.

```ts
import { Effect } from "effect";
import { JWA } from "@blissy-auth/jose";

const encoder = new TextEncoder();
const key = encoder.encode("super-secret-signing-key");
const payload = encoder.encode("hello world");

const signature = await Effect.runPromise(
  JWA.sign({
    alg: "HS256",
    key,
    payload,
  }),
);

const valid = await Effect.runPromise(
  JWA.verify({
    alg: "HS256",
    key,
    payload,
    signature,
  }),
);
```

Available attached types and errors:

- `JWA.Algorithm`
- `JWA.Key`
- `JWA.AlgorithmNotSupportedError`
- `JWA.KeyCompatibilityError`

## JWS

Use `JWS` for JOSE signature serializations.

### Compact JWS

```ts
import { Effect } from "effect";
import { JWS } from "@blissy-auth/jose";

const encoder = new TextEncoder();
const key = encoder.encode("super-secret-signing-key");
const payload = encoder.encode("hello world");

const token = await Effect.runPromise(
  JWS.signCompact({
    key,
    payload,
    protectedHeader: {
      alg: "HS256",
      typ: "JWT",
    },
  }),
);

const result = await Effect.runPromise(JWS.verifyCompact({ key, token }));
```

### JSON JWS

```ts
const flattened = await Effect.runPromise(
  JWS.signFlattened({
    key,
    payload,
    protectedHeader: { alg: "HS256" },
    header: { kid: "key-1" },
  }),
);

const general = await Effect.runPromise(
  JWS.signGeneral({
    payload,
    signatures: [
      {
        key,
        protectedHeader: { alg: "HS256" },
        header: { kid: "key-1" },
      },
    ],
  }),
);
```

Available attached types and errors:

- `JWS.Header`
- `JWS.HeaderValue`
- `JWS.VerificationError`
- `JWS.CriticalHeaderError`

## JWE

Use `JWE` for encrypted JOSE payloads.

### Compact JWE

```ts
import { Effect } from "effect";
import { JWE } from "@blissy-auth/jose";

const encoder = new TextEncoder();
const key = encoder.encode("0123456789abcdef0123456789abcdef");
const payload = encoder.encode("hello world");

const token = await Effect.runPromise(
  JWE.encryptCompact({
    key,
    payload,
    protectedHeader: {
      alg: "dir",
      enc: "A256GCM",
    },
  }),
);

const result = await Effect.runPromise(JWE.decryptCompact({ key, token }));
```

### JSON JWE

```ts
const flattened = await Effect.runPromise(
  JWE.encryptFlattened({
    key,
    payload,
    protectedHeader: {
      alg: "dir",
      enc: "A256GCM",
    },
    header: { kid: "key-1" },
  }),
);

const general = await Effect.runPromise(
  JWE.encryptGeneral({
    key,
    payload,
    protectedHeader: {
      alg: "dir",
      enc: "A256GCM",
    },
    recipients: [
      { header: { kid: "key-1" } },
      { header: { kid: "key-2" } },
    ],
  }),
);

const decrypted = await Effect.runPromise(
  JWE.decryptGeneral({
    key,
    kid: "key-2",
    serialization: general,
  }),
);
```

Available attached types and errors:

- `JWE.Algorithm`
- `JWE.Encryption`
- `JWE.Header`
- `JWE.HeaderValue`
- `JWE.Recipient`
- `JWE.AlgorithmNotSupportedError`
- `JWE.EncryptionNotSupportedError`
- `JWE.DecryptionError`

## JWT

Use `JWT` for claims-based tokens built on top of `JWS`.

### Sign and verify

```ts
import { Effect } from "effect";
import { JWT } from "@blissy-auth/jose";

const encoder = new TextEncoder();
const key = encoder.encode("super-secret-signing-key");

const token = await Effect.runPromise(
  JWT.sign({
    key,
    claims: {
      iss: "https://issuer.example",
      sub: "user-123",
      aud: "api",
      exp: 1_700_000_060,
      nbf: 1_700_000_000,
      iat: 1_700_000_000,
    },
  }),
);

const result = await Effect.runPromise(
  JWT.verify({
    token,
    key,
    issuer: "https://issuer.example",
    subject: "user-123",
    audience: "api",
    now: 1_700_000_010,
  }),
);
```

### Decode without verification

```ts
const decoded = await Effect.runPromise(JWT.decode({ token }));
```

### Allow unsecured JWTs explicitly

```ts
const result = await Effect.runPromise(
  JWT.verify({
    token,
    allowUnsecured: true,
  }),
);
```

Available attached types and errors:

- `JWT.Algorithm`
- `JWT.Claims`
- `JWT.Header`
- `JWT.HeaderValue`
- `JWT.DecodeError`
- `JWT.VerificationError`
- `JWT.ClaimValidationError`

## JWK

Use `JWK` for working with JWK Sets directly.

```ts
import { Effect } from "effect";
import { JWK } from "@blissy-auth/jose";

const set: JWK.Set = {
  keys: [
    {
      kty: "oct",
      kid: "sig-1",
      alg: "HS256",
      use: "sig",
      k: "c3VwZXItc2VjcmV0LXNpZ25pbmcta2V5",
    },
  ],
};

const parsed = await Effect.runPromise(JWK.parseSet(set));

const key = await Effect.runPromise(
  JWK.findKey({
    set: parsed,
    kid: "sig-1",
  }),
);
```

Available attached types and errors:

- `JWK.Value`
- `JWK.Key`
- `JWK.Set`
- `JWK.SetParseError`
- `JWK.KeyMatchError`

## JWKS

Use `JWKS` for JWKS-shaped documents with the same filtering behavior as `JWK`.

```ts
import { Effect } from "effect";
import { JWKS } from "@blissy-auth/jose";

const set: JWKS.Set = {
  keys: [
    {
      kty: "RSA",
      kid: "enc-1",
      alg: "RSA-OAEP",
      use: "enc",
      n: "modulus",
      e: "AQAB",
    },
  ],
};

const parsed = await Effect.runPromise(JWKS.parse(set));

const key = await Effect.runPromise(
  JWKS.findKey({
    set: parsed,
    kid: "enc-1",
  }),
);
```

Available attached types and errors:

- `JWKS.Value`
- `JWKS.Key`
- `JWKS.Set`
- `JWKS.ParseError`
- `JWKS.KeyMatchError`

## Error Handling

All APIs return `Effect`s and fail with tagged errors.

```ts
import { Effect } from "effect";
import { JWT } from "@blissy-auth/jose";

const outcome = await Effect.runPromise(
  Effect.match(JWT.verify({ token, key }), {
    onFailure: (error) => error,
    onSuccess: (value) => value,
  }),
);
```

## Notes

- This package currently implements a focused subset of JOSE rather than the entire standards surface.
- `JWS` currently signs with `HS256` only.
- `JWE` currently supports direct symmetric encryption with `dir` and `A256GCM` only.
- `JWT.sign` currently emits `HS256` tokens.
- `JWT.verify` can accept `alg: "none"` only when `allowUnsecured` is enabled explicitly.
