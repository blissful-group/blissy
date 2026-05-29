import { Effect } from "effect";

import { Base64 } from "../../utils/base64";
import { JWA } from "../jwa/jwa";
import type { JWAKey } from "../jwa/jwa.types";
import { JWSCriticalHeaderError, JWSVerificationError } from "./jws.errors";
import { Helper } from "./jws.helper";
import type { JWSHeader, JWSHeaderValue } from "./jws.types";

/**
 * Creates and verifies JSON Web Signatures using base64url encoding.
 */
export class JWS {
  private static Helper = Helper;

  static CriticalHeaderError = JWSCriticalHeaderError;
  static VerificationError = JWSVerificationError;

  private static encoder = new TextEncoder();
  private static decoder = new TextDecoder();

  /**
   * Creates a compact JWS serialization.
   */
  static signCompact(input: {
    key: JWAKey;
    payload: Uint8Array;
    protectedHeader: JWSHeader;
    header?: Record<string, JWSHeaderValue>;
  }) {
    return Effect.gen(function* () {
      const entry = yield* JWS.Helper.createSignatureEntry(input);

      return `${entry.protected}.${entry.payload}.${entry.signature}`;
    });
  }

  /**
   * Verifies a compact JWS serialization and returns its decoded payload and protected header.
   */
  static verifyCompact({ key, token }: { key: JWAKey; token: string }) {
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

      yield* JWS.Helper.validateCrit(protectedHeader);

      const signature = yield* Base64.decode(signatureSegment!);
      const valid = yield* JWA.verify({
        alg: protectedHeader.alg,
        key,
        payload: JWS.encoder.encode(`${protectedSegment}.${payloadSegment}`),
        signature,
      });

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
    key: JWAKey;
    payload: Uint8Array;
    protectedHeader: JWSHeader;
    header?: Record<string, JWSHeaderValue>;
  }) {
    return Effect.gen(function* () {
      const entry = yield* JWS.Helper.createSignatureEntry(input);

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
      key: JWAKey;
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
        const signatureBytes = yield* JWA.sign({
          alg: signatureInput.protectedHeader.alg,
          key: signatureInput.key,
          payload: JWS.encoder.encode(`${protectedSegment}.${payloadSegment}`),
        });
        const signature = yield* Base64.encode(signatureBytes);

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
}

export declare namespace JWS {
  export type Header = JWSHeader;
  export type HeaderValue = JWSHeaderValue;
}
