import { Schema } from "effect";

export const TokenErrorFieldSchema = Schema.String.pipe(
  Schema.pattern(/^[\u0020-\u0021\u0023-\u005B\u005D-\u007E]+$/u),
);

export const TokenErrorUriSchema = Schema.String.pipe(
  Schema.pattern(/^[\u0021\u0023-\u005B\u005D-\u007E]+$/u),
);

export const ExpiresInSchema = Schema.Number.pipe(Schema.nonNegative());
