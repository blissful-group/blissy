import { Effect } from "effect";

import { Base64 } from "../utils/base64";
import { SUPPORTED_CRITICAL_HEADERS } from "./jws.constants";
import { JWSCriticalHeaderError, JWSVerificationError } from "./jws.errors";
import type { JWSHeader, JWSHeaderValue } from "./jws.types";

export { JWSCriticalHeaderError, JWSVerificationError } from "./jws.errors";
export type { JWSHeader, JWSHeaderValue } from "./jws.types";

/**
 * Creates and verifies JSON Web Signatures using base64url encoding and HS256.
 */
export class JWS {
  private static encoder = new TextEncoder();
  private static decoder = new TextDecoder();

  /**
   * Creates a compact JWS serialization.
   */
  static signCompact(input: {
    key: Uint8Array;
    payload: Uint8Array;
    protectedHeader: JWSHeader;
    header?: Record<string, JWSHeaderValue>;
  }) {
    return Effect.gen(function* () {
      const entry = yield* JWS.createSignatureEntry(input);

      return `${entry.protected}.${entry.payload}.${entry.signature}`;
    });
  }

  /**
   * Verifies a compact JWS serialization and returns its decoded payload and protected header.
   */
  static verifyCompact({ key, token }: { key: Uint8Array; token: string }) {
    return Effect.gen(function* () {
      const segments = token.split(".");

      if (segments.length !== 3) {
        return yield* Effect.fail(
          new JWSVerificationError({
            message: "Invalid compact JWS serialization",
          }),
        );
      }

      const [protectedSegment, payloadSegment, signatureSegment] = segments;
      const protectedHeaderBytes = yield* Base64.decode(protectedSegment!);
      const protectedHeader = JSON.parse(
        JWS.decoder.decode(protectedHeaderBytes),
      ) as JWSHeader;

      yield* JWS.validateCrit(protectedHeader);

      const signature = yield* Base64.decode(signatureSegment!);
      const valid = yield* JWS.verify(
        key,
        `${protectedSegment}.${payloadSegment}`,
        signature,
      );

      if (!valid) {
        return yield* Effect.fail(
          new JWSVerificationError({
            message: "Invalid JWS signature",
          }),
        );
      }

      return {
        payload: yield* Base64.decode(payloadSegment!),
        protectedHeader,
      };
    });
  }

  /**
   * Creates a flattened JSON JWS serialization.
   */
  static signFlattened(input: {
    key: Uint8Array;
    payload: Uint8Array;
    protectedHeader: JWSHeader;
    header?: Record<string, JWSHeaderValue>;
  }) {
    return Effect.gen(function* () {
      const entry = yield* JWS.createSignatureEntry(input);

      return {
        header: entry.header,
        payload: entry.payload,
        protected: entry.protected,
        signature: entry.signature,
      };
    });
  }

  /**
   * Creates a general JSON JWS serialization with one or more signatures.
   */
  static signGeneral({
    payload,
    signatures,
  }: {
    payload: Uint8Array;
    signatures: Array<{
      key: Uint8Array;
      protectedHeader: JWSHeader;
      header?: Record<string, JWSHeaderValue>;
    }>;
  }) {
    return Effect.gen(function* () {
      const payloadSegment = yield* Base64.encode(payload);
      const serializedSignatures = [] as Array<{
        header?: Record<string, JWSHeaderValue>;
        protected: string;
        signature: string;
      }>;

      for (const signatureInput of signatures) {
        const protectedSegment = yield* Base64.encode(
          JWS.encoder.encode(JSON.stringify(signatureInput.protectedHeader)),
        );
        const signature = yield* JWS.sign(
          signatureInput.key,
          `${protectedSegment}.${payloadSegment}`,
        );

        serializedSignatures.push({
          header: signatureInput.header,
          protected: protectedSegment,
          signature,
        });
      }

      return {
        payload: payloadSegment,
        signatures: serializedSignatures,
      };
    });
  }

  private static importHmacKey(key: Uint8Array) {
    return Effect.promise(() =>
      crypto.subtle.importKey(
        "raw",
        new Uint8Array(key),
        {
          hash: "SHA-256",
          name: "HMAC",
        },
        false,
        ["sign", "verify"],
      ),
    );
  }

  private static sign(key: Uint8Array, signingInput: string) {
    return Effect.gen(function* () {
      const cryptoKey = yield* JWS.importHmacKey(key);
      const signature = yield* Effect.promise(() =>
        crypto.subtle.sign("HMAC", cryptoKey, JWS.encoder.encode(signingInput)),
      );

      return yield* Base64.encode(new Uint8Array(signature));
    });
  }

  private static verify(
    key: Uint8Array,
    signingInput: string,
    signature: Uint8Array,
  ) {
    return Effect.gen(function* () {
      const cryptoKey = yield* JWS.importHmacKey(key);

      return yield* Effect.promise(() =>
        crypto.subtle.verify(
          "HMAC",
          cryptoKey,
          new Uint8Array(signature),
          JWS.encoder.encode(signingInput),
        ),
      );
    });
  }

  private static validateCrit(protectedHeader: JWSHeader) {
    return Effect.gen(function* () {
      for (const criticalHeader of protectedHeader.crit ?? []) {
        if (!SUPPORTED_CRITICAL_HEADERS.has(criticalHeader)) {
          return yield* Effect.fail(
            new JWSCriticalHeaderError({
              message: `Unknown critical header parameter: "${criticalHeader}"`,
            }),
          );
        }
      }
    });
  }

  private static createSignatureEntry({
    header,
    key,
    payload,
    protectedHeader,
  }: {
    key: Uint8Array;
    payload: Uint8Array;
    protectedHeader: JWSHeader;
    header?: Record<string, JWSHeaderValue>;
  }) {
    return Effect.gen(function* () {
      const protectedSegment = yield* Base64.encode(
        JWS.encoder.encode(JSON.stringify(protectedHeader)),
      );
      const payloadSegment = yield* Base64.encode(payload);
      const signature = yield* JWS.sign(
        key,
        `${protectedSegment}.${payloadSegment}`,
      );

      return {
        header,
        payload: payloadSegment,
        protected: protectedSegment,
        signature,
      };
    });
  }
}
