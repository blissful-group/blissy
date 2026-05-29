import { Effect } from "effect";
import { expect, it } from "vitest";

import { OIDCUserInfoValidationError } from "./userinfo.errors";
import { Helper } from "./userinfo.helper";

it("parses UserInfo records", async () => {
  const record = await Effect.runPromise(
    Helper.parseRecord({ sub: "user-123" }),
  );

  expect(record.sub).toBe("user-123");
});

it("rejects invalid UserInfo records", async () => {
  const effect = Effect.match(Helper.parseRecord([]), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OIDCUserInfoValidationError);
  expect(error?.message).toBe("Invalid UserInfo response");
});

it("parses UserInfo subjects", async () => {
  await expect(
    Effect.runPromise(Helper.parseSubject("user-123")),
  ).resolves.toBe("user-123");
});

it("rejects invalid UserInfo subjects", async () => {
  const effect = Effect.match(Helper.parseSubject(""), {
    onFailure: (error) => error,
    onSuccess: () => null,
  });

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OIDCUserInfoValidationError);
  expect(error?._tag).toBe("OIDCUserInfoValidationError");
  expect(error?.message).toBe("Invalid UserInfo subject");
});
