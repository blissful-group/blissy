import { Effect } from "effect";

import { Base64 } from "../../utils/base64";
import { JWA } from "../jwa/jwa";
import type { JWAKey } from "../jwa/jwa.types";
import { SUPPORTED_CRITICAL_HEADERS } from "./jws.constants";
import { JWSCriticalHeaderError } from "./jws.errors";
import type { JWSHeader, JWSHeaderValue } from "./jws.types";

export class Helper {
  private static encoder = new TextEncoder();

  static validateCrit(protectedHeader: JWSHeader) {
    return Effect.gen(function* () {
      for (const criticalHeader of protectedHeader.crit ?? []) {
        if (SUPPORTED_CRITICAL_HEADERS.has(criticalHeader)) continue;

        const error = new JWSCriticalHeaderError({
          message: `Unknown critical header parameter: "${criticalHeader}"`,
        });

        return yield* Effect.fail(error);
      }
    });
  }

  static createSignatureEntry({
    header,
    key,
    payload,
    protectedHeader,
  }: {
    key: JWAKey;
    payload: Uint8Array;
    protectedHeader: JWSHeader;
    header?: Record<string, JWSHeaderValue>;
  }) {
    return Effect.gen(function* () {
      const protectedSegment = yield* Base64.encode(
        Helper.encoder.encode(JSON.stringify(protectedHeader)),
      );
      const payloadSegment = yield* Base64.encode(payload);
      const signatureBytes = yield* JWA.sign({
        alg: protectedHeader.alg,
        key,
        payload: Helper.encoder.encode(`${protectedSegment}.${payloadSegment}`),
      });
      const signature = yield* Base64.encode(signatureBytes);

      return {
        header,
        payload: payloadSegment,
        protected: protectedSegment,
        signature,
      };
    });
  }
}
