# @blissy-auth/crypto

Shared private Effect crypto service for Blissy workspace packages.

This package is not published. Source-code packages should import it through the source export:

```ts
import { AlgorithmReference, CryptoReference } from "@blissy-auth/crypto/source";
```

## Default Service

`CryptoReference` provides a default service backed by platform Web Crypto:

- `globalThis.crypto.getRandomValues`
- `globalThis.crypto.subtle.digest`
- `globalThis.crypto.subtle.importKey`
- `globalThis.crypto.subtle.sign`
- `globalThis.crypto.subtle.verify`
- `globalThis.crypto.subtle.encrypt`
- `globalThis.crypto.subtle.decrypt`

`AlgorithmReference` provides the Web Crypto algorithm descriptors used by workspace packages. This keeps algorithm selection injectable instead of hardcoded inside package operations.

## Override The Service

Use `Effect.provideService` to override individual crypto operations while keeping the rest of the default implementation.

```ts
import { CryptoReference } from "@blissy-auth/crypto/source";
import { Effect } from "effect";

const deterministicCrypto = {
  ...CryptoReference.defaultValue(),
  randomValues(bytes) {
    bytes.fill(0);

    return bytes;
  },
} satisfies CryptoReference.Service;

const program = someEffectUsingCrypto.pipe(
  Effect.provideService(CryptoReference, deterministicCrypto),
);
```

## Override Algorithms

Use `AlgorithmReference` to override algorithm descriptors separately from the crypto implementation.

```ts
import { AlgorithmReference } from "@blissy-auth/crypto/source";
import { Effect } from "effect";

const customAlgorithms = {
  ...AlgorithmReference.defaultValue(),
  digest: {
    sha256: "SHA-512",
  },
} satisfies AlgorithmReference.Service;

const program = someEffectUsingAlgorithms.pipe(
  Effect.provideService(AlgorithmReference, customAlgorithms),
);
```

This is mainly useful for deterministic tests or custom runtimes. Production callers normally rely on the default Web Crypto-backed service.

## Development

Run package tasks with Moon from the repository root.

```sh
moon run crypto:lint
moon run crypto:test
```
