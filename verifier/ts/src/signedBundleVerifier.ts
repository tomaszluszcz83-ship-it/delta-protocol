import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { canonicalizeJsonValue, type JsonObject, type JsonValue } from "./canonicalJson.js";
import { sha256PrefixedBytes } from "./hash.js";
import { decodeBytes, verifyEd25519Signature } from "./ed25519Verifier.js";
import { verifyDeltaBundle, type BundleVerificationResult } from "./bundleVerifier.js";

export const SIGNED_BUNDLE_PROFILE = "delta_typescript_signed_bundle_verifier_v2_9_4";

export interface SignedBundleVerificationResult {
  ok: boolean;
  profile: string;
  bundlePath: string;
  signaturePath: string;
  bundleIntegrityOk: boolean;
  signatureFileOk: boolean;
  signatureBodyHashOk: boolean | null;
  bundleHashBindingOk: boolean;
  publicKeyHashOk: boolean | null;
  signatureShapeOk: boolean;
  signatureOk: boolean;
  computedBundleHash: string;
  declaredBundleHash: string | null;
  declaredSignatureBodyHash: string | null;
  computedSignatureBodyHash: string | null;
  publicKeyHash: string | null;
  errors: string[];
  warnings: string[];
}

export class DeltaSignedBundleVerifierError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DeltaSignedBundleVerifierError";
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function sha256Prefixed(data: Buffer | string): string {
  return `sha256:${createHash("sha256").update(data).digest("hex")}`;
}

function normalizeHash(value: string): string {
  const trimmed = value.trim();
  return trimmed.startsWith("sha256:") ? trimmed : `sha256:${trimmed}`;
}

function readJsonObject(path: string): JsonObject {
  const parsed = JSON.parse(readFileSync(path, "utf-8")) as unknown;
  if (!isObject(parsed)) {
    throw new DeltaSignedBundleVerifierError(`signature file is not a JSON object: ${path}`);
  }
  return parsed as JsonObject;
}

function getObject(obj: Record<string, unknown>, name: string): JsonObject | null {
  const value = obj[name];
  return isObject(value) ? (value as JsonObject) : null;
}

function getString(obj: Record<string, unknown> | null, name: string): string | null {
  if (!obj) return null;
  const value = obj[name];
  return typeof value === "string" && value.length > 0 ? value : null;
}

function findStringRecursive(value: unknown, names: string[], maxDepth = 6): string | null {
  if (maxDepth < 0 || !isObject(value)) return null;

  for (const name of names) {
    const direct = value[name];
    if (typeof direct === "string" && direct.length > 0) {
      return direct;
    }
  }

  for (const nested of Object.values(value)) {
    if (isObject(nested)) {
      const found = findStringRecursive(nested, names, maxDepth - 1);
      if (found) return found;
    }
  }

  return null;
}

function signatureBodyHash(body: JsonObject): string {
  return sha256PrefixedBytes(canonicalizeJsonValue(body as JsonValue));
}

function publicKeyTextHash(publicKeyText: string): string {
  return sha256Prefixed(publicKeyText);
}

function signatureLooksHexOrBase64(value: string): boolean {
  const raw = value.includes(":") ? value.slice(value.indexOf(":") + 1) : value;
  if (/^[0-9a-fA-F]{128}$/.test(raw.trim())) return true;
  return raw.trim().length >= 80;
}

function messageCandidates(
  declaredBundleHash: string | null,
  computedBundleHash: string,
  declaredSignatureBodyHash: string | null,
  computedSignatureBodyHash: string | null,
  signatureBody: JsonObject | null
): Uint8Array[] {
  const candidates: Uint8Array[] = [];

  const addUtf8 = (value: string | null): void => {
    if (value) candidates.push(Uint8Array.from(Buffer.from(value, "utf-8")));
  };

  const addHashBytes = (value: string | null): void => {
    if (value && value.startsWith("sha256:")) {
      candidates.push(Uint8Array.from(Buffer.from(value.slice("sha256:".length), "hex")));
    }
  };

  if (signatureBody) {
    candidates.push(Uint8Array.from(Buffer.from(canonicalizeJsonValue(signatureBody as JsonValue), "utf-8")));
  }

  addUtf8(declaredBundleHash);
  addHashBytes(declaredBundleHash);
  addUtf8(computedBundleHash);
  addHashBytes(computedBundleHash);
  addUtf8(declaredSignatureBodyHash);
  addHashBytes(declaredSignatureBodyHash);
  addUtf8(computedSignatureBodyHash);
  addHashBytes(computedSignatureBodyHash);

  const unique = new Map<string, Uint8Array>();
  for (const candidate of candidates) {
    unique.set(Buffer.from(candidate).toString("hex"), candidate);
  }
  return [...unique.values()];
}

export async function verifySignedBundle(
  bundlePath: string,
  signaturePath: string,
  publicKeyOverride?: string
): Promise<SignedBundleVerificationResult> {
  const errors: string[] = [];
  const warnings: string[] = [];

  const bundleData = readFileSync(bundlePath);
  const computedBundleHash = sha256Prefixed(bundleData);

  let bundleIntegrity: BundleVerificationResult;
  try {
    bundleIntegrity = verifyDeltaBundle(bundlePath);
  } catch (err) {
    bundleIntegrity = {
      ok: false,
      profile: "delta_typescript_bundle_verifier_v2_9_3",
      bundlePath,
      manifestOk: false,
      artifactCount: 0,
      errors: [`bundle_verification_exception:${err instanceof Error ? err.message : "unknown"}`],
      warnings: []
    };
  }

  const bundleIntegrityOk = bundleIntegrity.ok;
  for (const bundleError of bundleIntegrity.errors) {
    errors.push(`bundle_integrity:${bundleError}`);
  }
  for (const bundleWarning of bundleIntegrity.warnings) {
    warnings.push(`bundle_integrity:${bundleWarning}`);
  }

  let sigJson: JsonObject | null = null;
  let signatureFileOk = false;

  try {
    sigJson = readJsonObject(signaturePath);
    signatureFileOk = true;
  } catch (err) {
    errors.push(`signature_file_read_or_parse_error:${err instanceof Error ? err.message : "unknown"}`);
  }

  const signatureBody = sigJson ? getObject(sigJson, "signature_body") : null;
  const signatureBlock = sigJson ? getObject(sigJson, "signature") : null;
  const selfCheck = sigJson ? getObject(sigJson, "self_check") : null;
  const bodyBundle = signatureBody ? getObject(signatureBody, "bundle") : null;
  const bodySigner = signatureBody ? getObject(signatureBody, "signer") : null;

  const declaredBundleHashRaw =
    getString(bodyBundle, "bundle_hash") ??
    getString(signatureBody, "bundle_hash") ??
    findStringRecursive(sigJson, ["delta_bundle_hash", "signed_bundle_hash"]);

  const declaredBundleHash = declaredBundleHashRaw ? normalizeHash(declaredBundleHashRaw) : null;
  const bundleHashBindingOk = declaredBundleHash === computedBundleHash;

  if (!declaredBundleHash) {
    errors.push("bundle_hash_missing_in_signature");
  } else if (!bundleHashBindingOk) {
    errors.push(`bundle_hash_mismatch:declared=${declaredBundleHash}:computed=${computedBundleHash}`);
  }

  const declaredSignatureBodyHashRaw =
    getString(sigJson, "signature_body_hash") ??
    getString(selfCheck, "signature_body_hash") ??
    getString(signatureBlock, "target_hash");

  const declaredSignatureBodyHash = declaredSignatureBodyHashRaw ? normalizeHash(declaredSignatureBodyHashRaw) : null;
  const computedSignatureBodyHash = signatureBody ? signatureBodyHash(signatureBody) : null;

  let signatureBodyHashOk: boolean | null = null;

  if (declaredSignatureBodyHash && computedSignatureBodyHash) {
    signatureBodyHashOk = declaredSignatureBodyHash === computedSignatureBodyHash;
    if (!signatureBodyHashOk) {
      errors.push(`signature_body_hash_mismatch:declared=${declaredSignatureBodyHash}:computed=${computedSignatureBodyHash}`);
    }
  } else if (declaredSignatureBodyHash || computedSignatureBodyHash) {
    signatureBodyHashOk = false;
    errors.push("signature_body_hash_incomplete");
  } else {
    warnings.push("signature_body_hash_not_declared");
  }

  const publicKeyValue =
    publicKeyOverride ??
    getString(bodySigner, "public_key") ??
    getString(signatureBlock, "public_key") ??
    findStringRecursive(sigJson, ["signer_public_key", "bundle_public_key", "ed25519_public_key", "public_key_hex"]);

  const declaredPublicKeyHashRaw =
    getString(bodySigner, "public_key_hash") ??
    getString(signatureBlock, "public_key_hash") ??
    findStringRecursive(sigJson, ["signer_public_key_hash", "bundle_public_key_hash", "ed25519_public_key_hash"]);

  let publicKeyHashOk: boolean | null = null;
  let actualPublicKeyHash: string | null = null;
  let publicKeyBytes: Uint8Array | null = null;

  if (!publicKeyValue) {
    errors.push("public_key_missing");
  } else {
    try {
      publicKeyBytes = decodeBytes(publicKeyValue);
      actualPublicKeyHash = publicKeyTextHash(publicKeyValue);

      if (declaredPublicKeyHashRaw) {
        const declaredPublicKeyHash = normalizeHash(declaredPublicKeyHashRaw);
        publicKeyHashOk = declaredPublicKeyHash === actualPublicKeyHash;
        if (!publicKeyHashOk) {
          errors.push(`public_key_hash_mismatch:declared=${declaredPublicKeyHash}:computed=${actualPublicKeyHash}`);
        }
      } else {
        publicKeyHashOk = null;
        warnings.push("public_key_hash_not_declared");
      }
    } catch (err) {
      errors.push(`public_key_decode_error:${err instanceof Error ? err.message : "unknown"}`);
    }
  }

  const signatureValue =
    getString(signatureBlock, "signature") ??
    getString(sigJson, "signature") ??
    findStringRecursive(sigJson, ["ed25519_signature", "signature_value", "bundle_signature", "detached_signature"]);

  let signatureShapeOk = false;
  let signatureOk = false;

  if (!signatureValue) {
    errors.push("signature_missing");
  } else if (!signatureLooksHexOrBase64(signatureValue)) {
    errors.push("signature_shape_invalid");
  } else {
    try {
      const signatureBytes = decodeBytes(signatureValue);
      signatureShapeOk = signatureBytes.length === 64;

      if (!signatureShapeOk) {
        errors.push(`signature_length_invalid:${signatureBytes.length}`);
      } else if (publicKeyBytes) {
        for (const message of messageCandidates(
          declaredBundleHash,
          computedBundleHash,
          declaredSignatureBodyHash,
          computedSignatureBodyHash,
          signatureBody
        )) {
          if (verifyEd25519Signature(signatureBytes, message, publicKeyBytes)) {
            signatureOk = true;
            break;
          }
        }

        if (!signatureOk) {
          errors.push("signature_invalid");
        }
      }
    } catch (err) {
      errors.push(`signature_verification_error:${err instanceof Error ? err.message : "unknown"}`);
    }
  }

  const ok =
    bundleIntegrityOk &&
    signatureFileOk &&
    bundleHashBindingOk &&
    signatureShapeOk &&
    signatureOk &&
    (signatureBodyHashOk !== false) &&
    (publicKeyHashOk !== false);

  return {
    ok,
    profile: SIGNED_BUNDLE_PROFILE,
    bundlePath,
    signaturePath,
    bundleIntegrityOk,
    signatureFileOk,
    signatureBodyHashOk,
    bundleHashBindingOk,
    publicKeyHashOk,
    signatureShapeOk,
    signatureOk,
    computedBundleHash,
    declaredBundleHash,
    declaredSignatureBodyHash,
    computedSignatureBodyHash,
    publicKeyHash: actualPublicKeyHash,
    errors,
    warnings
  };
}
