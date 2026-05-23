import { Data } from "effect";

export class JWEAlgorithmNotSupportedError extends Data.TaggedError(
  "JWEAlgorithmNotSupportedError",
)<{
  message: `Unsupported JWE algorithm: "${string}"`;
}> {}

export class JWEEncryptionNotSupportedError extends Data.TaggedError(
  "JWEEncryptionNotSupportedError",
)<{
  message: `Unsupported JWE encryption: "${string}"`;
}> {}

export class JWEDecryptionError extends Data.TaggedError("JWEDecryptionError")<{
  message:
    | "Invalid JWE ciphertext"
    | `No JWE recipient matched kid: "${string}"`;
}> {}
