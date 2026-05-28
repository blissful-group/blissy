import type {
  A256GCM,
  ES256,
  HS256,
  RS256,
  SHA256,
} from "./algorithm.constants";

export type AlgorithmService = {
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
