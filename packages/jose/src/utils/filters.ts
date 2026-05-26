export class Filters {
  static keys({ alg, kid, kty, use }: Filters.Input) {
    return <T extends Filters.Input>(key: T) => {
      if (kid !== undefined && key.kid !== kid) return false;
      if (alg !== undefined && key.alg !== alg) return false;
      if (kty !== undefined && key.kty !== kty) return false;
      if (use !== undefined && key.use !== use) return false;

      return true;
    };
  }
}

export declare namespace Filters {
  export type Key = "alg" | "kid" | "kty" | "use";
  export type Input = { [k in Filters.Key]?: string };
}
