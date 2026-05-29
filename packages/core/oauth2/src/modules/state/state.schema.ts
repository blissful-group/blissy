import { Schema } from "effect";

export const StateByteLengthSchema = Schema.Number.pipe(
  Schema.int(),
  Schema.positive(),
);
