import { Effect } from "effect";
import { expect, it } from "vitest";

import { OIDCCallback } from "./callback";

it("parses an authorization code callback", async () => {
  const callback = await Effect.runPromise(
    OIDCCallback.authorizationCode({
      callbackUrl:
        "https://client.example/callback?code=code-123&state=state-123",
      expectedState: "state-123",
    }),
  );

  expect(callback).toEqual({
    code: "code-123",
    state: "state-123",
    type: "success",
  });
});

it("parses an authorization error callback", async () => {
  const callback = await Effect.runPromise(
    OIDCCallback.authorizationCode({
      callbackUrl:
        "https://client.example/callback?error=access_denied&state=state-123",
      expectedState: "state-123",
    }),
  );

  expect(callback).toEqual({
    error: "access_denied",
    errorDescription: undefined,
    errorUri: undefined,
    state: "state-123",
    type: "error",
  });
});
