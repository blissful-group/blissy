import { Schema } from "effect";

export const NonceByteLengthSchema = Schema.Number.pipe(
  Schema.int(),
  Schema.positive(),
);
