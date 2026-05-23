export type JWKSValue = string | number | boolean | null | string[];

export type JWKSKey = Record<string, unknown> & {
  kty: string;
  kid?: string;
  alg?: string;
  use?: string;
};

export type JWKSSet = {
  keys: JWKSKey[];
};
