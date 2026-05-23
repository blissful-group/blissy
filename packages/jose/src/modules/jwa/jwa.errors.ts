import { Data } from "effect";

export class JWAAlgorithmNotSupportedError extends Data.TaggedError(
  "JWAAlgorithmNotSupportedError",
)<{
  message: `Unsupported JWA algorithm: "${string}"`;
}> {}

export class JWAKeyCompatibilityError extends Data.TaggedError(
  "JWAKeyCompatibilityError",
)<{
  message: `Key is incompatible with JWA algorithm: "${string}"`;
}> {}
