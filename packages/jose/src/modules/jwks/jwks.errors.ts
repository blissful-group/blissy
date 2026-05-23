import { Data } from "effect";

export class JWKSParseError extends Data.TaggedError("JWKSParseError")<{
  message: "Invalid JWKS: missing keys array";
}> {}

export class JWKSKeyMatchError extends Data.TaggedError("JWKSKeyMatchError")<{
  message: "Multiple JWKS keys matched the given criteria";
}> {}
