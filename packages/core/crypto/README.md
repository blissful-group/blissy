[Back to root](https://github.com/blissful-group/blissy)

# <img src="https://raw.githubusercontent.com/blissful-group/blissy/main/assets/blissy.png" alt="" width="28" />- [@blissy-auth/crypto](https://github.com/blissful-group/blissy/blob/main/packages/core/crypto)

![NPM License](https://img.shields.io/npm/l/@blissy-auth/crypto)
![NPM Unpacked Size](https://img.shields.io/npm/unpacked-size/@blissy-auth/crypto)

Shared Effect crypto service for Blissy workspace packages.

This package provides injectable Web Crypto-backed services for Blissy packages. It is primarily intended for internal package composition, tests, and custom runtimes.

## Install

```bash
pnpm add @blissy-auth/crypto effect
```

```bash
npm install @blissy-auth/crypto effect
```

## Basic Usage

```ts
import { AlgorithmReference, CryptoReference } from "@blissy-auth/crypto";
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
import { CryptoReference } from "@blissy-auth/crypto";
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
import { AlgorithmReference } from "@blissy-auth/crypto";
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
