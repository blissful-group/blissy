import { Data } from "effect";

export class OIDCAuthorizationRequestValidationError extends Data.TaggedError(
  "OIDCAuthorizationRequestValidationError",
)<{
  message: "Invalid OIDC authorization request parameter";
  parameter: string;
}> {}
