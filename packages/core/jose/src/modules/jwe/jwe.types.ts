export type JWEAlgorithm = "dir";

export type JWEEncryption = "A256GCM";

export type JWEHeaderValue = string | number | boolean | null | string[];

export type JWEHeader = Record<string, JWEHeaderValue> & {
  alg: JWEAlgorithm;
  enc: JWEEncryption;
};

export type JWERecipient = {
  encrypted_key: string;
  header?: Record<string, JWEHeaderValue>;
};
