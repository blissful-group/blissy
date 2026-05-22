import {
  BASE64_URL_ALPHABET,
  BASE64_URL_CHARACTERS,
  WHITESPACE_PATTERN,
} from "./utils/constants";

export class Base64 {
  static encode(bytes: Uint8Array): string {
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
  }

  static decode(input: string): Uint8Array {
    if (WHITESPACE_PATTERN.test(input)) {
      throw new Error("Invalid base64url string: whitespace is not allowed");
    }

    if (!BASE64_URL_CHARACTERS.test(input)) {
      throw new Error(
        "Invalid base64url string: contains non-URL-safe characters",
      );
    }

    if (input.length % 4 === 1) {
      throw new Error("Invalid base64url string: malformed input");
    }

    const output: number[] = [];

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

      output.push((a << 2) | (b >> 4));

      if (c !== undefined) {
        output.push(((b & 0b1111) << 4) | (c >> 2));
      }

      if (d !== undefined && c !== undefined) {
        output.push(((c & 0b11) << 6) | d);
      }
    }

    return Uint8Array.from(output);
  }
}
