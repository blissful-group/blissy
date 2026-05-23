import { Data } from "effect";

export class JWSVerificationError extends Data.TaggedError(
  "JWSVerificationError",
)<{
  message: "Invalid JWS signature" | "Invalid compact JWS serialization";
}> {}

export class JWSCriticalHeaderError extends Data.TaggedError(
  "JWSCriticalHeaderError",
)<{
  message: `Unknown critical header parameter: "${string}"`;
}> {}
