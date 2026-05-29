import { Data } from "effect";

export class OAuth2ClientAuthenticationError extends Data.TaggedError(
  "OAuth2ClientAuthenticationError",
)<{
  message:
    | "Invalid OAuth2 client id"
    | "Invalid OAuth2 client secret"
    | "Invalid OAuth2 client authentication";
}> {}
