import { Effect } from "effect";

import {
  BASE64_URL_ALPHABET,
  BASE64_URL_CHARACTERS,
  WHITESPACE_PATTERN,
} from "./base64.constants";
import { Base64DecodeError } from "./base64.errors";

export class Base64 {
  static encode(bytes: Uint8Array) {
    return Effect.sync(() => {
      let output = "";

      for (let index = 0; index < bytes.length; index += 3) {
        const a = bytes[index]!;
        const b = bytes[index + 1];
        const c = bytes[index + 2];

        output += BASE64_URL_ALPHABET[a >> 2];
        output += BASE64_URL_ALPHABET[((a & 0b11) << 4) | ((b ?? 0) >> 4)];

        if (b !== undefined) {
          output += BASE64_URL_ALPHABET[((b & 0b1111) << 2) | ((c ?? 0) >> 6)];
        }

        if (c !== undefined) {
          output += BASE64_URL_ALPHABET[c & 0b111111];
        }
      }

      return output;
    });
  }

  static decode(input: string) {
    return Effect.gen(function* () {
      if (WHITESPACE_PATTERN.test(input)) {
        const error = new Base64DecodeError({
          message: "Invalid base64url string: whitespace is not allowed",
        });

        return yield* Effect.fail(error);
      }

      if (!BASE64_URL_CHARACTERS.test(input)) {
        const error = new Base64DecodeError({
          message: "Invalid base64url string: contains non-URL-safe characters",
        });

        return yield* Effect.fail(error);
      }

      if (input.length % 4 === 1) {
        const error = new Base64DecodeError({
          message: "Invalid base64url string: malformed input",
        });

        return yield* Effect.fail(error);
      }

      const fullChunksLength = Math.floor(input.length / 4) * 3;
      const trailingChunkLength = Math.max(0, (input.length % 4) - 1);
      const outputLength = fullChunksLength + trailingChunkLength;
      const output = new Uint8Array(outputLength);
      let outputIndex = 0;

      for (let index = 0; index < input.length; index += 4) {
        const a = BASE64_URL_ALPHABET.indexOf(input[index]!);
        const b = BASE64_URL_ALPHABET.indexOf(input[index + 1]!);
        const c =
          input[index + 2] === undefined
            ? undefined
            : BASE64_URL_ALPHABET.indexOf(input[index + 2]);
        const d =
          input[index + 3] === undefined
            ? undefined
            : BASE64_URL_ALPHABET.indexOf(input[index + 3]);

        output[outputIndex] = (a << 2) | (b >> 4);
        outputIndex += 1;

        if (c !== undefined) {
          output[outputIndex] = ((b & 0b1111) << 4) | (c >> 2);
          outputIndex += 1;
        }

        if (d !== undefined && c !== undefined) {
          output[outputIndex] = ((c & 0b11) << 6) | d;
          outputIndex += 1;
        }
      }

      return output;
    });
  }
}
