import { createHash, createPublicKey, verify as nodeVerify } from "node:crypto";

export class DeltaEd25519VerifierError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DeltaEd25519VerifierError";
  }
}

const ED25519_SPKI_PREFIX_HEX = "302a300506032b6570032100";

export function sha256Hex(data: Uint8Array | string): string {
  const hash = createHash("sha256");
  hash.update(data);
  return hash.digest("hex");
}

export function publicKeyHash(publicKey: Uint8Array): string {
  return `sha256:${sha256Hex(publicKey)}`;
}

function normalizeBase64Url(value: string): string {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const pad = normalized.length % 4;
  return pad === 0 ? normalized : normalized + "=".repeat(4 - pad);
}

export function decodeBytes(value: string, preferredPrefix?: string): Uint8Array {
  let raw = value.trim();

  if (preferredPrefix && raw.startsWith(`${preferredPrefix}:`)) {
    raw = raw.slice(preferredPrefix.length + 1);
  } else if (raw.includes(":")) {
    raw = raw.slice(raw.indexOf(":") + 1);
  }

  if (/^[0-9a-fA-F]+$/.test(raw) && raw.length % 2 === 0) {
    return Uint8Array.from(Buffer.from(raw, "hex"));
  }

  try {
    return Uint8Array.from(Buffer.from(normalizeBase64Url(raw), "base64"));
  } catch (err) {
    throw new DeltaEd25519VerifierError("could not decode byte string as hex/base64/base64url");
  }
}

export function encodeEd25519Hex(bytes: Uint8Array): string {
  return `ed25519:${Buffer.from(bytes).toString("hex")}`;
}

export function rawEd25519PublicKeyToSpkiDer(publicKey: Uint8Array): Buffer {
  if (publicKey.length !== 32) {
    throw new DeltaEd25519VerifierError(`Ed25519 public key must be 32 bytes, got ${publicKey.length}`);
  }

  return Buffer.concat([
    Buffer.from(ED25519_SPKI_PREFIX_HEX, "hex"),
    Buffer.from(publicKey)
  ]);
}

export function verifyEd25519Signature(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array
): boolean {
  if (signature.length !== 64) {
    throw new DeltaEd25519VerifierError(`Ed25519 signature must be 64 bytes, got ${signature.length}`);
  }

  const key = createPublicKey({
    key: rawEd25519PublicKeyToSpkiDer(publicKey),
    format: "der",
    type: "spki"
  });

  return nodeVerify(null, Buffer.from(message), key, Buffer.from(signature));
}
