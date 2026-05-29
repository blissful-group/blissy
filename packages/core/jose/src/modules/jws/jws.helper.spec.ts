import { Effect } from "effect";
import { expect, it } from "vitest";

import { JWSCriticalHeaderError } from "./jws.errors";
import { Helper } from "./jws.helper";

it("allows supported critical headers", async () => {
  await Effect.runPromise(
    Helper.validateCrit({ alg: "HS256", crit: ["alg"], typ: "JWT" }),
  );
});

it("rejects unknown critical headers", async () => {
  const effect = Effect.match(
    Helper.validateCrit({ alg: "HS256", crit: ["unknown"], typ: "JWT" }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(JWSCriticalHeaderError);
  expect(error?._tag).toBe("JWSCriticalHeaderError");
  expect(error?.message).toBe('Unknown critical header parameter: "unknown"');
});
