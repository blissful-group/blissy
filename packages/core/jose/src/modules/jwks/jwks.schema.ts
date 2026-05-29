import { Schema } from "effect";

export const JWKSKeySchema = Schema.Struct({
  kty: Schema.String,
}).pipe(
  Schema.extend(Schema.Record({ key: Schema.String, value: Schema.Unknown })),
);

export const JWKSSetSchema = Schema.Struct({
  keys: Schema.Array(JWKSKeySchema),
});
