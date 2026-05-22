import { expect, it } from "vitest";

import { Base64 } from "./base64";

it("encodes bytes using URL-safe base64 without padding", () => {
  const singleByte = Uint8Array.of(255);
  const doubleByte = Uint8Array.of(251, 255);
  const tripleByte = Uint8Array.of(251, 255, 190);

  const singleByteResult = Base64.encode(singleByte);
  const doubleByteResult = Base64.encode(doubleByte);
  const tripleByteResult = Base64.encode(tripleByte);

  expect(singleByteResult).toBe("_w");
  expect(doubleByteResult).toBe("-_8");
  expect(tripleByteResult).toBe("-_--");
});

it("decodes URL-safe base64 without padding", () => {
  const singleByteInput = "_w";
  const doubleByteInput = "-_8";
  const tripleByteInput = "-_--";
  const emptyInput = "";

  const singleByteResult = Base64.decode(singleByteInput);
  const doubleByteResult = Base64.decode(doubleByteInput);
  const tripleByteResult = Base64.decode(tripleByteInput);
  const emptyResult = Base64.decode(emptyInput);

  expect(singleByteResult).toEqual(Uint8Array.of(255));
  expect(doubleByteResult).toEqual(Uint8Array.of(251, 255));
  expect(tripleByteResult).toEqual(Uint8Array.of(251, 255, 190));
  expect(emptyResult).toEqual(new Uint8Array());
});

it("rejects base64url input containing whitespace", () => {
  const input = "-_8\n";

  const action = () => Base64.decode(input);

  expect(action).toThrow("Invalid base64url string: whitespace is not allowed");
});

it("rejects base64url input containing non-url-safe characters", () => {
  const input = "+/8";

  const action = () => Base64.decode(input);

  expect(action).toThrow(
    "Invalid base64url string: contains non-URL-safe characters",
  );
});

it("rejects malformed base64url input", () => {
  const input = "A";

  const action = () => Base64.decode(input);

  expect(action).toThrow("Invalid base64url string: malformed input");
});
