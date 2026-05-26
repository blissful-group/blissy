import { Data } from "effect";

export class OAuth2TokenResponseValidationError extends Data.TaggedError(
  "OAuth2TokenResponseValidationError",
)<{
  message:
    | "Invalid token response"
    | "Invalid token error"
    | "Invalid token error URI"
    | "Invalid access token"
    | "Invalid token type"
    | "Invalid expires_in";
}> {}
