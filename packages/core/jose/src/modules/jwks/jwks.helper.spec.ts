import { Effect } from "effect";
import { expect, it } from "vitest";

import { JWKSKeyMatchError } from "./jwks.errors";
import { Helper } from "./jwks.helper";

it("finds a single matching JWKS key", async () => {
  const key = await Effect.runPromise(
    Helper.findSingleMatch({
      args: { kid: "sig-1" },
      keys: [
        { kty: "RSA", kid: "sig-1" },
        { kty: "RSA", kid: "sig-2" },
      ],
    }),
  );

  expect(key?.kid).toBe("sig-1");
});

it("rejects multiple matching JWKS keys", async () => {
  const effect = Effect.match(
    Helper.findSingleMatch({
      args: { use: "sig" },
      keys: [
        { kty: "RSA", kid: "sig-1", use: "sig" },
        { kty: "RSA", kid: "sig-2", use: "sig" },
      ],
    }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWKSKeyMatchError);
  expect(error?._tag).toBe("JWKSKeyMatchError");
  expect(error?.message).toBe("Multiple JWKS keys matched the given criteria");
});
