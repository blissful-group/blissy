import { Data } from "effect";

export class OAuth2ScopeValidationError extends Data.TaggedError(
  "OAuth2ScopeValidationError",
)<{
  message: "Invalid OAuth2 scope";
  scope: string;
}> {}
