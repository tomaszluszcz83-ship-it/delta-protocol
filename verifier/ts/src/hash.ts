import { createHash } from "node:crypto";

export function sha256HexBytes(data: Uint8Array | string): string {
  const hash = createHash("sha256");
  hash.update(data);
  return hash.digest("hex");
}

export function sha256PrefixedBytes(data: Uint8Array | string): string {
  return `sha256:${sha256HexBytes(data)}`;
}
