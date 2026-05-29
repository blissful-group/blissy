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
