import { Data } from "effect";

export class OAuth2TokenIntrospectionRequestValidationError extends Data.TaggedError(
  "OAuth2TokenIntrospectionRequestValidationError",
)<{
  message:
    | "Invalid introspection endpoint"
    | "Invalid token"
    | "Invalid token type hint"
    | "Invalid token introspection request parameter";
  parameter?: string;
}> {}
