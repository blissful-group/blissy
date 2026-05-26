import { Schema } from "effect";

export const ScopeValueSchema = Schema.String.pipe(
  Schema.pattern(/^[\x21\x23-\x5B\x5D-\x7E]+$/u),
);
