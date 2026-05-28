export type JWKValue = string | number | boolean | null | string[];

export type JWKKey = Record<string, unknown> & {
  kty: string;
  kid?: string;
  alg?: string;
  use?: string;
  key_ops?: string[];
};

export type JWKSet = {
  keys: JWKKey[];
};
