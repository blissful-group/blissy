import { Schema } from "effect";

export const JWKKeySchema = Schema.Struct({
  kty: Schema.String,
}).pipe(
  Schema.extend(Schema.Record({ key: Schema.String, value: Schema.Unknown })),
);

export const JWKSetSchema = Schema.Struct({
  keys: Schema.Array(JWKKeySchema),
});
