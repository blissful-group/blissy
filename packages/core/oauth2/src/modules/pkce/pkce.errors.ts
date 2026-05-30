import { Data } from "effect";

import type { CodeChallengeMethodSchema } from "./pkce.schema";

export class CodeVerifierValidationError extends Data.TaggedError(
  "CodeVerifierValidationError",
)<{
  message:
    | "Invalid PKCE code verifier length"
    | "Invalid PKCE code verifier characters";
}> {}

export class CodeChallengeMethodError extends Data.TaggedError(
  "CodeChallengeMethodError",
)<{
  message: "Unsupported PKCE code challenge method";
  method: string;
}> {}

export class CodeChallengeVerificationError extends Data.TaggedError(
  "CodeChallengeVerificationError",
)<{
  message: "Invalid PKCE code challenge";
  method: typeof CodeChallengeMethodSchema.Type;
}> {}
