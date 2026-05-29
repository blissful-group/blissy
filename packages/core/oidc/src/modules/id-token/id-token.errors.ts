import { Data } from "effect";

export class OIDCIDTokenValidationError extends Data.TaggedError(
  "OIDCIDTokenValidationError",
)<{
  message:
    | "Invalid ID token issuer"
    | "Invalid ID token subject"
    | "Invalid ID token audience"
    | "Invalid ID token expiration"
    | "Invalid ID token issued at"
    | "Invalid ID token nonce"
    | "Invalid ID token authorized party";
}> {}
