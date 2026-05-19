import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { canonicalizeJsonValue, parseStrictJson, type JsonObject, type JsonValue } from "./canonicalJson.js";
import { decodeBytes, verifyEd25519Signature } from "./ed25519Verifier.js";
import {
  verifyIntentRegistryBinding,
  type IntentRegistryVerificationResult,
  type IntentRegistryVerificationStatus
} from "./intentRegistryVerifier.js";

export const INTENT_VERIFIER_PROFILE = "delta_typescript_intent_verifier_mvp_v2_12_2";

export type RecordHashBindingMethod = "file_sha256" | "canonical_json_sha256" | null;
export type IntentSignatureVerificationStatus = "NOT_PROVIDED" | "VERIFIED" | "INVALID";

export interface IntentVerificationResult {
  ok: boolean;
  profile: string;
  recordPath: string;
  intentPath: string;
  signaturePath: string | null;
  registryPath: string | null;
  intentFileOk: boolean;
  recordFileOk: boolean;
  declaredRecordHash: string | null;
  computedRecordFileHash: string | null;
  computedRecordCanonicalHash: string | null;
  recordHashBindingOk: boolean;
  recordHashBindingMethod: RecordHashBindingMethod;
  intentStatus: string | null;
  intentProfile: string | null;
  intentPurpose: string | null;
  computedIntentCanonicalHash: string | null;
  signatureFileOk: boolean | null;
  declaredIntentHash: string | null;
  intentHashBindingOk: boolean | null;
  declaredSignatureBodyHash: string | null;
  computedSignatureBodyHash: string | null;
  signatureBodyHashOk: boolean | null;
  publicKeyHashOk: boolean | null;
  signatureShapeOk: boolean | null;
  signatureOk: boolean | null;
  signerLabel: string | null;
  signerPublicKey: string | null;
  signerPublicKeyHash: string | null;
  signatureVerificationStatus: IntentSignatureVerificationStatus;
  registryVerificationStatus: IntentRegistryVerificationStatus;
  registryResult: IntentRegistryVerificationResult | null;
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

function publicKeyTextHash(publicKeyText: string): string {
  return sha256PrefixedBytes(publicKeyText);
}

function signatureLooksHexOrBase64(value: string): boolean {
  const raw = value.includes(":") ? value.slice(value.indexOf(":") + 1) : value;
  if (/^[0-9a-fA-F]{128}$/.test(raw.trim())) return true;
  return raw.trim().length >= 80;
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

export function computeIntentCanonicalHashFromObject(intent: JsonObject): string {
  return sha256PrefixedBytes(canonicalizeJsonValue(intent as JsonValue));
}

function computeSignatureBodyHash(signatureBody: JsonObject): string {
  return sha256PrefixedBytes(canonicalizeJsonValue(signatureBody as JsonValue));
}

function verifyDetachedIntentSignature(
  signaturePath: string,
  computedIntentCanonicalHash: string | null,
  declaredRecordHash: string | null,
  errors: string[],
  warnings: string[]
): {
  signatureFileOk: boolean;
  declaredIntentHash: string | null;
  intentHashBindingOk: boolean;
  declaredSignatureBodyHash: string | null;
  computedSignatureBodyHash: string | null;
  signatureBodyHashOk: boolean;
  publicKeyHashOk: boolean | null;
  signatureShapeOk: boolean;
  signatureOk: boolean;
  signerLabel: string | null;
  signerPublicKey: string | null;
  signerPublicKeyHash: string | null;
} {
  let signatureFileOk = false;
  let sigJson: JsonObject | null = null;

  try {
    sigJson = readJsonObject(signaturePath);
    signatureFileOk = true;
  } catch (err) {
    errors.push(`intent_signature_file_error:${err instanceof Error ? err.message : "unknown"}`);
  }

  const signatureBody = sigJson ? getObject(sigJson, "signature_body") ?? getObject(sigJson, "body") : null;
  const signatureBlock = sigJson ? getObject(sigJson, "signature") : null;
  const selfCheck = sigJson ? getObject(sigJson, "self_check") : null;
  const bodyIntent = getObject(signatureBody, "intent");
  const bodyRecord = getObject(signatureBody, "record");
  const bodySigner = getObject(signatureBody, "signer");

  const declaredIntentHashRaw =
    getString(bodyIntent, "intent_hash") ??
    getString(signatureBody, "intent_hash") ??
    getString(sigJson, "intent_hash") ??
    findStringRecursive(sigJson, ["target_intent_hash", "intent_attestation_hash", "attestation_hash"]);

  const declaredIntentHash = declaredIntentHashRaw ? normalizeHash(declaredIntentHashRaw) : null;
  const intentHashBindingOk = Boolean(declaredIntentHash && computedIntentCanonicalHash && declaredIntentHash === computedIntentCanonicalHash);

  if (!declaredIntentHash) {
    errors.push("intent_signature_intent_hash_missing");
  } else if (!intentHashBindingOk) {
    errors.push(`intent_signature_intent_hash_mismatch:declared=${declaredIntentHash}:computed=${computedIntentCanonicalHash ?? "unavailable"}`);
  }

  const signatureRecordHashRaw =
    getString(bodyRecord, "record_hash") ??
    getString(signatureBody, "record_hash");

  if (signatureRecordHashRaw && declaredRecordHash) {
    const signatureRecordHash = normalizeHash(signatureRecordHashRaw);
    if (signatureRecordHash !== declaredRecordHash) {
      errors.push(`intent_signature_record_hash_mismatch:signature=${signatureRecordHash}:intent=${declaredRecordHash}`);
    }
  } else {
    warnings.push("intent_signature_record_hash_not_declared");
  }

  const declaredSignatureBodyHashRaw =
    getString(sigJson, "signature_body_hash") ??
    getString(selfCheck, "signature_body_hash") ??
    getString(signatureBlock, "target_hash");

  const declaredSignatureBodyHash = declaredSignatureBodyHashRaw ? normalizeHash(declaredSignatureBodyHashRaw) : null;
  const computedSignatureBodyHash = signatureBody ? computeSignatureBodyHash(signatureBody) : null;
  const signatureBodyHashOk = Boolean(
    declaredSignatureBodyHash &&
    computedSignatureBodyHash &&
    declaredSignatureBodyHash === computedSignatureBodyHash
  );

  if (!signatureBody) {
    errors.push("intent_signature_body_missing");
  }

  if (!declaredSignatureBodyHash) {
    errors.push("intent_signature_body_hash_missing");
  } else if (!signatureBodyHashOk) {
    errors.push(`intent_signature_body_hash_mismatch:declared=${declaredSignatureBodyHash}:computed=${computedSignatureBodyHash ?? "unavailable"}`);
  }

  const publicKeyValue =
    getString(bodySigner, "public_key") ??
    getString(signatureBlock, "public_key") ??
    findStringRecursive(sigJson, ["signer_public_key", "intent_public_key", "ed25519_public_key"]);

  const declaredPublicKeyHashRaw =
    getString(bodySigner, "public_key_hash") ??
    getString(signatureBlock, "public_key_hash") ??
    findStringRecursive(sigJson, ["signer_public_key_hash", "intent_public_key_hash", "ed25519_public_key_hash"]);

  let publicKeyBytes: Uint8Array | null = null;
  let publicKeyHashOk: boolean | null = null;
  let signerPublicKeyHash: string | null = null;

  if (!publicKeyValue) {
    errors.push("intent_signature_public_key_missing");
  } else {
    try {
      publicKeyBytes = decodeBytes(publicKeyValue);
      signerPublicKeyHash = publicKeyTextHash(publicKeyValue);

      if (declaredPublicKeyHashRaw) {
        const declaredPublicKeyHash = normalizeHash(declaredPublicKeyHashRaw);
        publicKeyHashOk = declaredPublicKeyHash === signerPublicKeyHash;
        if (!publicKeyHashOk) {
          errors.push(`intent_signature_public_key_hash_mismatch:declared=${declaredPublicKeyHash}:computed=${signerPublicKeyHash}`);
        }
      } else {
        warnings.push("intent_signature_public_key_hash_not_declared");
      }
    } catch (err) {
      errors.push(`intent_signature_public_key_decode_error:${err instanceof Error ? err.message : "unknown"}`);
    }
  }

  const signatureValue =
    getString(signatureBlock, "signature") ??
    getString(sigJson, "signature") ??
    findStringRecursive(sigJson, ["ed25519_signature", "signature_value", "intent_signature", "detached_signature"]);

  let signatureShapeOk = false;
  let signatureOk = false;

  if (!signatureValue) {
    errors.push("intent_signature_missing");
  } else if (!signatureLooksHexOrBase64(signatureValue)) {
    errors.push("intent_signature_shape_invalid");
  } else {
    try {
      const signatureBytes = decodeBytes(signatureValue);
      signatureShapeOk = signatureBytes.length === 64;

      if (!signatureShapeOk) {
        errors.push(`intent_signature_length_invalid:${signatureBytes.length}`);
      } else if (publicKeyBytes && signatureBody) {
        const message = Uint8Array.from(Buffer.from(canonicalizeJsonValue(signatureBody as JsonValue), "utf-8"));
        signatureOk = verifyEd25519Signature(signatureBytes, message, publicKeyBytes);

        if (!signatureOk) {
          errors.push("intent_signature_invalid");
        }
      }
    } catch (err) {
      errors.push(`intent_signature_verification_error:${err instanceof Error ? err.message : "unknown"}`);
    }
  }

  return {
    signatureFileOk,
    declaredIntentHash,
    intentHashBindingOk,
    declaredSignatureBodyHash,
    computedSignatureBodyHash,
    signatureBodyHashOk,
    publicKeyHashOk,
    signatureShapeOk,
    signatureOk,
    signerLabel: getString(bodySigner, "label") ?? getString(signatureBlock, "signer") ?? null,
    signerPublicKey: publicKeyValue,
    signerPublicKeyHash
  };
}

export function verifyIntentBinding(
  recordPath: string,
  intentPath: string,
  signaturePath?: string,
  registryPath?: string
): IntentVerificationResult {
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

  const computedIntentCanonicalHash = intent ? computeIntentCanonicalHashFromObject(intent) : null;

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
  let recordHashBindingMethod: RecordHashBindingMethod = null;

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

  let signatureFileOk: boolean | null = null;
  let declaredIntentHash: string | null = null;
  let intentHashBindingOk: boolean | null = null;
  let declaredSignatureBodyHash: string | null = null;
  let computedSignatureBodyHash: string | null = null;
  let signatureBodyHashOk: boolean | null = null;
  let publicKeyHashOk: boolean | null = null;
  let signatureShapeOk: boolean | null = null;
  let signatureOk: boolean | null = null;
  let signerLabel: string | null = null;
  let signerPublicKey: string | null = null;
  let signerPublicKeyHash: string | null = null;
  let signatureVerificationStatus: "NOT_PROVIDED" | "VERIFIED" | "INVALID" = "NOT_PROVIDED";

  if (signaturePath) {
    const sig = verifyDetachedIntentSignature(
      signaturePath,
      computedIntentCanonicalHash,
      declaredRecordHash,
      errors,
      warnings
    );

    signatureFileOk = sig.signatureFileOk;
    declaredIntentHash = sig.declaredIntentHash;
    intentHashBindingOk = sig.intentHashBindingOk;
    declaredSignatureBodyHash = sig.declaredSignatureBodyHash;
    computedSignatureBodyHash = sig.computedSignatureBodyHash;
    signatureBodyHashOk = sig.signatureBodyHashOk;
    publicKeyHashOk = sig.publicKeyHashOk;
    signatureShapeOk = sig.signatureShapeOk;
    signatureOk = sig.signatureOk;
    signerLabel = sig.signerLabel;
    signerPublicKey = sig.signerPublicKey;
    signerPublicKeyHash = sig.signerPublicKeyHash;

    signatureVerificationStatus =
      sig.signatureFileOk &&
      sig.intentHashBindingOk &&
      sig.signatureBodyHashOk &&
      sig.signatureShapeOk &&
      sig.signatureOk &&
      (sig.publicKeyHashOk !== false)
        ? "VERIFIED"
        : "INVALID";
  } else {
    warnings.push("intent_detached_signature_not_provided");
  }

  let registryResult: IntentRegistryVerificationResult | null = null;
  let registryVerificationStatus: IntentRegistryVerificationStatus = "NOT_PROVIDED";

  if (registryPath) {
    if (!signaturePath) {
      errors.push("intent_registry_requires_detached_signature");
      registryVerificationStatus = "INVALID";
    } else {
      registryResult = verifyIntentRegistryBinding({
        registryPath,
        signerLabel,
        signerPublicKey,
        signerPublicKeyHash
      });

      registryVerificationStatus = registryResult.registryVerificationStatus;

      for (const registryError of registryResult.errors) {
        errors.push(`intent_registry:${registryError}`);
      }
      for (const registryWarning of registryResult.warnings) {
        warnings.push(`intent_registry:${registryWarning}`);
      }
    }
  }

  const signatureRequiredOk =
    !signaturePath ||
    (
      signatureFileOk === true &&
      intentHashBindingOk === true &&
      signatureBodyHashOk === true &&
      signatureShapeOk === true &&
      signatureOk === true &&
      publicKeyHashOk !== false
    );

  const registryRequiredOk =
    !registryPath ||
    registryVerificationStatus === "VERIFIED";

  const ok = intentFileOk && recordFileOk && recordHashBindingOk && signatureRequiredOk && registryRequiredOk;

  return {
    ok,
    profile: INTENT_VERIFIER_PROFILE,
    recordPath,
    intentPath,
    signaturePath: signaturePath ?? null,
    registryPath: registryPath ?? null,
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
    computedIntentCanonicalHash,
    signatureFileOk,
    declaredIntentHash,
    intentHashBindingOk,
    declaredSignatureBodyHash,
    computedSignatureBodyHash,
    signatureBodyHashOk,
    publicKeyHashOk,
    signatureShapeOk,
    signatureOk,
    signerLabel,
    signerPublicKey,
    signerPublicKeyHash,
    signatureVerificationStatus,
    registryVerificationStatus,
    registryResult,
    errors,
    warnings
  };
}
