import { Effect } from "effect";
import { expect, it } from "vitest";

import { JWKKeyMatchError } from "./jwk.errors";
import { Helper } from "./jwk.helper";

it("finds a single matching JWK", async () => {
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

it("rejects multiple matching JWKs", async () => {
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

  expect(error).toBeInstanceOf(JWKKeyMatchError);
  expect(error?._tag).toBe("JWKKeyMatchError");
  expect(error?.message).toBe("Multiple JWKs matched the given criteria");
});
