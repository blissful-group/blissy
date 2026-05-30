import { Context } from "effect";

import { A256GCM, ES256, HS256, RS256, SHA256 } from "./algorithm.constants";
import { defaultValue } from "./algorithm.defaults";

export class AlgorithmReference extends Context.Reference<AlgorithmReference>()(
  "@blissy-auth/crypto/AlgorithmReference",
  { defaultValue },
) {
  static A256GCM = A256GCM;
  static ES256 = ES256;
  static HS256 = HS256;
  static RS256 = RS256;
  static SHA256 = SHA256;
}

export namespace AlgorithmReference {
  export type Service = {
    digest: {
      [SHA256]: AlgorithmIdentifier;
    };
    jwa: {
      [HS256]: {
        importKey: HmacImportParams;
        sign: AlgorithmIdentifier;
      };
      [RS256]: {
        importKey: RsaHashedImportParams;
        sign: AlgorithmIdentifier;
      };
      [ES256]: {
        importKey: EcKeyImportParams;
        sign: EcdsaParams;
      };
    };
    jwe: {
      [A256GCM]: {
        importKey: AesKeyAlgorithm;
        params: (input: {
          iv: Uint8Array<ArrayBuffer>;
          additionalData?: Uint8Array<ArrayBuffer>;
        }) => AesGcmParams;
      };
    };
  };
}
