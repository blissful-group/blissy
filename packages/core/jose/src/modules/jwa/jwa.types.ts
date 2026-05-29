import type { AlgorithmReference } from "@blissy-auth/crypto/source";

export type JWAAlgorithm =
  | typeof AlgorithmReference.HS256
  | typeof AlgorithmReference.RS256
  | typeof AlgorithmReference.ES256;

export type JWAKey = CryptoKey | Uint8Array;
