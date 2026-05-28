import { Effect } from "effect";
import { expect, it } from "vitest";

import { AlgorithmReference } from "./algorithm";

it("provides default digest algorithms", async () => {
  const algorithm = await Effect.runPromise(AlgorithmReference);

  expect(AlgorithmReference.SHA256).toBe("SHA256");
  expect(algorithm.digest[AlgorithmReference.SHA256]).toBe("SHA-256");
});

it("provides default JWA algorithms", async () => {
  const algorithm = await Effect.runPromise(AlgorithmReference);

  expect(AlgorithmReference.HS256).toBe("HS256");
  expect(AlgorithmReference.RS256).toBe("RS256");
  expect(AlgorithmReference.ES256).toBe("ES256");
  expect(algorithm.jwa[AlgorithmReference.HS256].importKey).toEqual({
    hash: "SHA-256",
    name: "HMAC",
  });
  expect(algorithm.jwa[AlgorithmReference.HS256].sign).toBe("HMAC");
  expect(algorithm.jwa[AlgorithmReference.RS256].importKey).toEqual({
    hash: "SHA-256",
    name: "RSASSA-PKCS1-v1_5",
  });
  expect(algorithm.jwa[AlgorithmReference.RS256].sign).toBe(
    "RSASSA-PKCS1-v1_5",
  );
  expect(algorithm.jwa[AlgorithmReference.ES256].importKey).toEqual({
    name: "ECDSA",
    namedCurve: "P-256",
  });
  expect(algorithm.jwa[AlgorithmReference.ES256].sign).toEqual({
    hash: "SHA-256",
    name: "ECDSA",
  });
});

it("provides default JWE algorithms", async () => {
  const algorithm = await Effect.runPromise(AlgorithmReference);
  const iv = new Uint8Array(12);
  const additionalData = new Uint8Array([1, 2, 3]);

  expect(AlgorithmReference.A256GCM).toBe("A256GCM");
  expect(algorithm.jwe[AlgorithmReference.A256GCM].importKey).toEqual({
    length: 256,
    name: "AES-GCM",
  });
  expect(
    algorithm.jwe[AlgorithmReference.A256GCM].params({ additionalData, iv }),
  ).toEqual({
    additionalData,
    iv,
    name: "AES-GCM",
    tagLength: 128,
  });
});
