import { Data } from "effect";

export class AuthorizationResponseValidationError extends Data.TaggedError(
  "AuthorizationResponseValidationError",
)<{
  message:
    | "Invalid authorization callback URL"
    | "Invalid authorization response"
    | "Invalid authorization error"
    | "Invalid authorization error description"
    | "Invalid authorization error URI"
    | "Duplicate authorization response parameter"
    | "Unsupported authorization response mode";
  parameter?: string;
  responseMode?: string;
}> {}
