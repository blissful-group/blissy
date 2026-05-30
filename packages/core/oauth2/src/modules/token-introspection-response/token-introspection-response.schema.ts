import { Schema } from "effect";

export const IntrospectionStringListClaimSchema = Schema.Union(
  Schema.String,
  Schema.Array(Schema.String),
);

export const IntrospectionTimestampClaimSchema = Schema.Number.pipe(
  Schema.nonNegative(),
);
