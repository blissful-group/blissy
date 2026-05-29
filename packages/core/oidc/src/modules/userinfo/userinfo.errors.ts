import { Data } from "effect";

export class OIDCUserInfoValidationError extends Data.TaggedError(
  "OIDCUserInfoValidationError",
)<{
  message: "Invalid UserInfo response" | "Invalid UserInfo subject";
}> {}
