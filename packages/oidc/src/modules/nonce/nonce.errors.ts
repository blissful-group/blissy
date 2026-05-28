import { Data } from "effect";

export class OIDCNonceGenerationError extends Data.TaggedError(
  "OIDCNonceGenerationError",
)<{
  message: "Invalid OIDC nonce byte length";
  byteLength: number;
}> {}

export class OIDCNonceValidationError extends Data.TaggedError(
  "OIDCNonceValidationError",
)<{
  message: "Missing OIDC nonce" | "Invalid OIDC nonce";
}> {}
