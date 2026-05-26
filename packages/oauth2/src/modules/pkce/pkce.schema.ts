import { Schema } from "effect";

export const CodeChallengeMethodSchema = Schema.Literal("plain", "S256");

export const CodeVerifierLengthSchema = Schema.String.pipe(
  Schema.minLength(43),
  Schema.maxLength(128),
);

export const CodeVerifierCharactersSchema = Schema.String.pipe(
  Schema.pattern(/^[A-Za-z0-9._~-]+$/u),
);
