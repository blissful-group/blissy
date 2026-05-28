import { Data } from "effect";

export class JWKSetParseError extends Data.TaggedError("JWKSetParseError")<{
  message: "Invalid JWK Set: missing keys array";
}> {}

export class JWKKeyMatchError extends Data.TaggedError("JWKKeyMatchError")<{
  message: "Multiple JWKs matched the given criteria";
}> {}

export class JWKKeyImportError extends Data.TaggedError("JWKKeyImportError")<{
  message: "Invalid JWK key";
}> {}
