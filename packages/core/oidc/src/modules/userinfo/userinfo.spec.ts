import { Effect } from "effect";
import { expect, it } from "vitest";

import { OIDCUserInfo } from "./userinfo";

it("parses a UserInfo response", async () => {
  const userinfo = await Effect.runPromise(
    OIDCUserInfo.parse({
      email: "user@example.com",
      email_verified: true,
      sub: "user-123",
    }),
  );

  expect(userinfo).toEqual({
    email: "user@example.com",
    email_verified: true,
    sub: "user-123",
  });
});

it("rejects missing UserInfo subject", async () => {
  const effect = Effect.match(
    OIDCUserInfo.parse({ email: "user@example.com" }),
    {
      onFailure: (error) => error,
      onSuccess: () => null,
    },
  );

  const error = await Effect.runPromise(effect);

  expect(error).toBeInstanceOf(OIDCUserInfo.ValidationError);
  expect(error?._tag).toBe("OIDCUserInfoValidationError");
  expect(error?.message).toBe("Invalid UserInfo subject");
});
