import { Data } from "effect";

export class OAuth2TokenRevocationRequestValidationError extends Data.TaggedError(
  "OAuth2TokenRevocationRequestValidationError",
)<{
  message:
    | "Invalid revocation endpoint"
    | "Invalid token"
    | "Invalid token type hint"
    | "Invalid token revocation request parameter";
  parameter?: string;
}> {}
