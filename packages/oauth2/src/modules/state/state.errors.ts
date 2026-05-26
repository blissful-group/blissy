import { Data } from "effect";

export class OAuth2StateGenerationError extends Data.TaggedError(
  "OAuth2StateGenerationError",
)<{
  message: "Invalid OAuth2 state byte length";
  byteLength: number;
}> {}

export class OAuth2StateValidationError extends Data.TaggedError(
  "OAuth2StateValidationError",
)<{
  message:
    | "Missing OAuth2 state"
    | "Unexpected OAuth2 state"
    | "Invalid OAuth2 state";
}> {}
