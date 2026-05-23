export type JWSHeaderValue = string | number | boolean | null | string[];

export type JWSHeader = Record<string, JWSHeaderValue> & {
  alg: "HS256";
  crit?: string[];
};
