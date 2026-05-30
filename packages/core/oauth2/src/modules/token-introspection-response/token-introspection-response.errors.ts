import { Data } from "effect";

export class OAuth2TokenIntrospectionResponseValidationError extends Data.TaggedError(
  "OAuth2TokenIntrospectionResponseValidationError",
)<{
  message:
    | "Invalid token introspection response"
    | "Invalid active flag"
    | "Invalid token scope"
    | "Invalid token type"
    | "Invalid token introspection string claim"
    | "Invalid token introspection string list claim"
    | "Invalid token introspection timestamp claim";
  claim?: string;
}> {}
