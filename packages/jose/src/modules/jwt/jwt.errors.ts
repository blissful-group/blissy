import { Data } from "effect";

export class JWTDecodeError extends Data.TaggedError("JWTDecodeError")<{
  message: "Invalid JWT";
}> {}

export class JWTVerificationError extends Data.TaggedError(
  "JWTVerificationError",
)<{
  message: "Unsigned JWTs are not allowed" | "Invalid JWT signature";
}> {}

export class JWTClaimValidationError extends Data.TaggedError(
  "JWTClaimValidationError",
)<{
  message:
    | 'Invalid JWT claim "iss"'
    | 'Invalid JWT claim "sub"'
    | 'Invalid JWT claim "aud"'
    | 'Invalid JWT claim "exp"'
    | 'Invalid JWT claim "nbf"'
    | 'Invalid JWT claim "iat"';
}> {}
