import { Data } from "effect";

export class AuthorizationRequestValidationError extends Data.TaggedError(
  "AuthorizationRequestValidationError",
)<{
  message:
    | "Invalid authorization endpoint"
    | "Invalid client id"
    | "Invalid redirect uri"
    | "Invalid authorization request parameter";
  parameter?: string;
}> {}
