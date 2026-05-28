export type CryptoService = {
  randomValues: (bytes: Uint8Array<ArrayBuffer>) => Uint8Array<ArrayBuffer>;
  digest: (
    algorithm: AlgorithmIdentifier,
    data: BufferSource,
  ) => Promise<ArrayBuffer>;
  importKey: SubtleCrypto["importKey"];
  sign: SubtleCrypto["sign"];
  verify: SubtleCrypto["verify"];
  encrypt: SubtleCrypto["encrypt"];
  decrypt: SubtleCrypto["decrypt"];
};
