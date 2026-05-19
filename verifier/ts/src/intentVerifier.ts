import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { canonicalizeJsonValue, parseStrictJson, type JsonObject, type JsonValue } from "./canonicalJson.js";

export const INTENT_VERIFIER_PROFILE = "delta_typescript_intent_verifier_mvp_v2_12_0";

export interface IntentVerificationResult {
  ok: boolean;
  profile: string;
  recordPath: string;
  intentPath: string;
  intentFileOk: boolean;
  recordFileOk: boolean;
  declaredRecordHash: string | null;
  computedRecordFileHash: string | null;
  computedRecordCanonicalHash: string | null;
  recordHashBindingOk: boolean;
  recordHashBindingMethod: "file_sha256" | "canonical_json_sha256" | null;
  intentStatus: string | null;
  intentProfile: string | null;
  intentPurpose: string | null;
  signaturePresent: boolean;
  signatureVerificationStatus: "NOT_IMPLEMENTED" | "NOT_PRESENT";
  errors: string[];
  warnings: string[];
}

export class DeltaIntentVerifierError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DeltaIntentVerifierError";
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function sha256PrefixedBytes(data: Buffer | Uint8Array | string): string {
  return `sha256:${createHash("sha256").update(data).digest("hex")}`;
}

function normalizeHash(value: string): string {
  const trimmed = value.trim();
  return trimmed.startsWith("sha256:") ? trimmed : `sha256:${trimmed}`;
}

function readJsonObject(path: string): JsonObject {
  const text = readFileSync(path, "utf-8");
  const parsed = parseStrictJson(text);
  if (!isObject(parsed)) {
    throw new DeltaIntentVerifierError(`JSON file is not an object: ${path}`);
  }
  return parsed as JsonObject;
}

function getString(obj: Record<string, unknown> | null, name: string): string | null {
  if (!obj) return null;
  const value = obj[name];
  return typeof value === "string" && value.length > 0 ? value : null;
}

function getObject(obj: Record<string, unknown> | null, name: string): JsonObject | null {
  if (!obj) return null;
  const value = obj[name];
  return isObject(value) ? (value as JsonObject) : null;
}

function findStringRecursive(value: unknown, names: string[], maxDepth = 8): string | null {
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

function hasSignatureLikeField(value: unknown, maxDepth = 8): boolean {
  if (maxDepth < 0 || !isObject(value)) return false;

  for (const [key, nested] of Object.entries(value)) {
    const lower = key.toLowerCase();
    if (
      lower === "signature" ||
      lower === "intent_signature" ||
      lower === "detached_signature" ||
      lower === "ed25519_signature"
    ) {
      if (typeof nested === "string" && nested.length > 0) return true;
      if (isObject(nested)) return true;
    }

    if (isObject(nested) && hasSignatureLikeField(nested, maxDepth - 1)) {
      return true;
    }
  }

  return false;
}

export function computeRecordFileHash(recordPath: string): string {
  return sha256PrefixedBytes(readFileSync(recordPath));
}

export function computeRecordCanonicalHash(recordPath: string): string | null {
  try {
    const record = readJsonObject(recordPath);
    return sha256PrefixedBytes(canonicalizeJsonValue(record as JsonValue));
  } catch {
    return null;
  }
}

export function verifyIntentBinding(recordPath: string, intentPath: string): IntentVerificationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  let intent: JsonObject | null = null;
  let intentFileOk = false;

  try {
    intent = readJsonObject(intentPath);
    intentFileOk = true;
  } catch (err) {
    errors.push(`intent_file_error:${err instanceof Error ? err.message : "unknown"}`);
  }

  let computedRecordFileHash: string | null = null;
  let computedRecordCanonicalHash: string | null = null;
  let recordFileOk = false;

  try {
    computedRecordFileHash = computeRecordFileHash(recordPath);
    computedRecordCanonicalHash = computeRecordCanonicalHash(recordPath);
    recordFileOk = true;
  } catch (err) {
    errors.push(`record_file_error:${err instanceof Error ? err.message : "unknown"}`);
  }

  const intentBody = intent ? getObject(intent, "intent_body") ?? getObject(intent, "body") : null;
  const bindingObject =
    getObject(intentBody, "record") ??
    getObject(intentBody, "target_record") ??
    getObject(intent, "record") ??
    getObject(intent, "target_record");

  const declaredRecordHashRaw = intent
    ? getString(bindingObject, "record_hash") ??
      getString(bindingObject, "delta_record_hash") ??
      getString(intentBody, "record_hash") ??
      getString(intentBody, "target_record_hash") ??
      getString(intent, "record_hash") ??
      getString(intent, "target_record_hash") ??
      getString(intent, "delta_record_hash") ??
      findStringRecursive(intent, [
        "record_hash",
        "target_record_hash",
        "delta_record_hash",
        "full_record_hash",
        "bound_record_hash"
      ])
    : null;

  const declaredRecordHash = declaredRecordHashRaw ? normalizeHash(declaredRecordHashRaw) : null;

  let recordHashBindingOk = false;
  let recordHashBindingMethod: "file_sha256" | "canonical_json_sha256" | null = null;

  if (!declaredRecordHash) {
    errors.push("intent_record_hash_missing");
  } else if (computedRecordFileHash && declaredRecordHash === computedRecordFileHash) {
    recordHashBindingOk = true;
    recordHashBindingMethod = "file_sha256";
  } else if (computedRecordCanonicalHash && declaredRecordHash === computedRecordCanonicalHash) {
    recordHashBindingOk = true;
    recordHashBindingMethod = "canonical_json_sha256";
    warnings.push("intent_bound_to_canonical_record_hash_not_raw_file_hash");
  } else {
    errors.push(
      `intent_record_hash_mismatch:declared=${declaredRecordHash}:file=${computedRecordFileHash ?? "unavailable"}:canonical=${computedRecordCanonicalHash ?? "unavailable"}`
    );
  }

  const intentStatus = intent
    ? getString(intent, "status") ??
      getString(intentBody, "status") ??
      findStringRecursive(intent, ["intent_status", "attestation_status"])
    : null;

  const intentProfile = intent
    ? getString(intent, "profile") ??
      getString(intent, "signature_profile") ??
      getString(intentBody, "profile") ??
      findStringRecursive(intent, ["intent_profile", "attestation_profile"])
    : null;

  const intentPurpose = intent
    ? getString(intent, "purpose") ??
      getString(intentBody, "purpose") ??
      findStringRecursive(intent, ["intent_purpose"])
    : null;

  const signaturePresent = intent ? hasSignatureLikeField(intent) : false;

  if (signaturePresent) {
    warnings.push("intent_signature_present_but_signature_verification_not_implemented_in_v2_12_0_mvp");
  } else {
    warnings.push("intent_signature_not_present_or_not_checked");
  }

  const ok = intentFileOk && recordFileOk && recordHashBindingOk;

  return {
    ok,
    profile: INTENT_VERIFIER_PROFILE,
    recordPath,
    intentPath,
    intentFileOk,
    recordFileOk,
    declaredRecordHash,
    computedRecordFileHash,
    computedRecordCanonicalHash,
    recordHashBindingOk,
    recordHashBindingMethod,
    intentStatus,
    intentProfile,
    intentPurpose,
    signaturePresent,
    signatureVerificationStatus: signaturePresent ? "NOT_IMPLEMENTED" : "NOT_PRESENT",
    errors,
    warnings
  };
}
