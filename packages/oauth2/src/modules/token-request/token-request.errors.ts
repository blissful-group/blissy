import { Data } from "effect";

export class OAuth2TokenRequestValidationError extends Data.TaggedError(
  "OAuth2TokenRequestValidationError",
)<{
  message:
    | "Invalid token endpoint"
    | "Invalid authorization code"
    | "Invalid refresh token"
    | "Invalid PKCE code verifier"
    | "Invalid token request parameter";
  parameter?: string;
}> {}
