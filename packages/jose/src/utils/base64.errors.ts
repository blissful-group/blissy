import { Data } from "effect";

export class Base64DecodeError extends Data.TaggedError("Base64DecodeError")<{
  message:
    | "Invalid base64url string: whitespace is not allowed"
    | "Invalid base64url string: contains non-URL-safe characters"
    | "Invalid base64url string: malformed input";
}> {}
