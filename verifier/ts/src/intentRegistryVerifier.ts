import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { parseStrictJson, type JsonObject } from "./canonicalJson.js";

export const INTENT_REGISTRY_PROFILE = "delta_typescript_intent_registry_binding_v2_12_2";

export type IntentRegistryVerificationStatus = "NOT_PROVIDED" | "VERIFIED" | "INVALID";

export interface IntentRegistryVerificationInput {
  registryPath: string;
  signerLabel: string | null;
  signerPublicKey: string | null;
  signerPublicKeyHash: string | null;
}

export interface IntentRegistryVerificationResult {
  ok: boolean;
  profile: string;
  registryPath: string;
  registryFileOk: boolean;
  registryEntryFound: boolean;
  registryVerificationStatus: IntentRegistryVerificationStatus;
  matchedEntryLabel: string | null;
  matchedEntryStatus: string | null;
  matchedEntryRole: string | null;
  signerLabel: string | null;
  signerPublicKeyHash: string | null;
  registryPublicKeyHash: string | null;
  registryPublicKeyHashOk: boolean | null;
  registryPublicKeyOk: boolean | null;
  registryStatusOk: boolean | null;
  errors: string[];
  warnings: string[];
}

export class DeltaIntentRegistryVerifierError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DeltaIntentRegistryVerifierError";
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function getString(obj: Record<string, unknown> | null, name: string): string | null {
  if (!obj) return null;
  const value = obj[name];
  return typeof value === "string" && value.length > 0 ? value : null;
}

function getArray(obj: Record<string, unknown> | null, name: string): unknown[] | null {
  if (!obj) return null;
  const value = obj[name];
  return Array.isArray(value) ? value : null;
}

function normalizeHash(value: string): string {
  const trimmed = value.trim();
  return trimmed.startsWith("sha256:") ? trimmed : `sha256:${trimmed}`;
}

function sha256Prefixed(data: string): string {
  return `sha256:${createHash("sha256").update(data).digest("hex")}`;
}

function readJsonObject(path: string): JsonObject {
  const parsed = parseStrictJson(readFileSync(path, "utf-8"));
  if (!isObject(parsed)) {
    throw new DeltaIntentRegistryVerifierError(`registry JSON is not an object: ${path}`);
  }
  return parsed as JsonObject;
}

interface RegistryEntry {
  label: string | null;
  keyId: string | null;
  role: string | null;
  status: string | null;
  publicKey: string | null;
  publicKeyHash: string | null;
}

function entryFromObject(obj: Record<string, unknown>): RegistryEntry {
  const publicKey = getString(obj, "public_key") ?? getString(obj, "ed25519_public_key") ?? getString(obj, "intent_public_key");
  const declaredHash = getString(obj, "public_key_hash") ?? getString(obj, "ed25519_public_key_hash") ?? getString(obj, "intent_public_key_hash");
  const publicKeyHash = declaredHash ? normalizeHash(declaredHash) : publicKey ? sha256Prefixed(publicKey) : null;

  return {
    label: getString(obj, "label") ?? getString(obj, "name") ?? getString(obj, "signer") ?? getString(obj, "signer_label"),
    keyId: getString(obj, "key_id") ?? getString(obj, "id") ?? getString(obj, "kid"),
    role: getString(obj, "role"),
    status: getString(obj, "status"),
    publicKey,
    publicKeyHash
  };
}

function collectEntries(registry: JsonObject): RegistryEntry[] {
  const entries: RegistryEntry[] = [];

  for (const arrayName of ["entries", "signers", "keys", "public_keys"]) {
    const arr = getArray(registry, arrayName);
    if (!arr) continue;

    for (const item of arr) {
      if (isObject(item)) {
        entries.push(entryFromObject(item));
      }
    }
  }

  const signerMap = registry["signers"];
  if (isObject(signerMap) && !Array.isArray(signerMap)) {
    for (const [label, item] of Object.entries(signerMap)) {
      if (isObject(item)) {
        const entry = entryFromObject(item);
        entries.push({
          ...entry,
          label: entry.label ?? label
        });
      }
    }
  }

  const keyMap = registry["keys"];
  if (isObject(keyMap) && !Array.isArray(keyMap)) {
    for (const [keyId, item] of Object.entries(keyMap)) {
      if (isObject(item)) {
        const entry = entryFromObject(item);
        entries.push({
          ...entry,
          keyId: entry.keyId ?? keyId
        });
      }
    }
  }

  return entries;
}

function statusIsActive(status: string | null): boolean {
  if (!status) return true;
  return ["active", "valid", "trusted", "enabled"].includes(status.toLowerCase());
}

export function verifyIntentRegistryBinding(input: IntentRegistryVerificationInput): IntentRegistryVerificationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  let registryFileOk = false;
  let registry: JsonObject | null = null;

  try {
    registry = readJsonObject(input.registryPath);
    registryFileOk = true;
  } catch (err) {
    errors.push(`intent_registry_file_error:${err instanceof Error ? err.message : "unknown"}`);
  }

  if (!input.signerPublicKeyHash) {
    errors.push("intent_registry_signer_public_key_hash_missing");
  }

  const entries = registry ? collectEntries(registry) : [];
  if (registry && entries.length === 0) {
    errors.push("intent_registry_no_entries");
  }

  const signerHash = input.signerPublicKeyHash ? normalizeHash(input.signerPublicKeyHash) : null;

  const labelMatches = input.signerLabel
    ? entries.filter((entry) => entry.label === input.signerLabel)
    : [];

  const hashMatches = signerHash
    ? entries.filter((entry) => entry.publicKeyHash === signerHash)
    : [];

  let matched: RegistryEntry | null = null;

  if (labelMatches.length > 0 && signerHash) {
    matched = labelMatches.find((entry) => entry.publicKeyHash === signerHash) ?? null;

    if (!matched) {
      errors.push(`intent_registry_label_found_but_public_key_hash_mismatch:${input.signerLabel}`);
      matched = labelMatches[0] ?? null;
    }
  } else if (labelMatches.length > 0) {
    matched = labelMatches[0] ?? null;
  } else if (hashMatches.length > 0) {
    matched = hashMatches[0] ?? null;
    warnings.push("intent_registry_matched_by_public_key_hash_without_label");
  }

  const registryEntryFound = Boolean(matched);

  if (!registryEntryFound) {
    errors.push(
      `intent_registry_entry_not_found:label=${input.signerLabel ?? "null"}:public_key_hash=${signerHash ?? "null"}`
    );
  }

  const registryPublicKeyHash = matched?.publicKeyHash ?? null;
  const registryPublicKeyHashOk =
    matched && signerHash && matched.publicKeyHash
      ? matched.publicKeyHash === signerHash
      : matched
        ? null
        : false;

  if (matched && registryPublicKeyHashOk === false) {
    errors.push(`intent_registry_public_key_hash_mismatch:registry=${matched.publicKeyHash}:signer=${signerHash}`);
  }

  const registryPublicKeyOk =
    matched && input.signerPublicKey && matched.publicKey
      ? matched.publicKey === input.signerPublicKey
      : matched
        ? null
        : false;

  if (matched && registryPublicKeyOk === false) {
    errors.push("intent_registry_public_key_mismatch");
  }

  const registryStatusOk = matched ? statusIsActive(matched.status) : false;

  if (matched && !registryStatusOk) {
    errors.push(`intent_registry_entry_not_active:status=${matched.status ?? "null"}`);
  }

  const ok =
    registryFileOk &&
    registryEntryFound &&
    registryStatusOk === true &&
    registryPublicKeyHashOk !== false &&
    registryPublicKeyOk !== false &&
    errors.length === 0;

  return {
    ok,
    profile: INTENT_REGISTRY_PROFILE,
    registryPath: input.registryPath,
    registryFileOk,
    registryEntryFound,
    registryVerificationStatus: ok ? "VERIFIED" : "INVALID",
    matchedEntryLabel: matched?.label ?? null,
    matchedEntryStatus: matched?.status ?? null,
    matchedEntryRole: matched?.role ?? null,
    signerLabel: input.signerLabel,
    signerPublicKeyHash: signerHash,
    registryPublicKeyHash,
    registryPublicKeyHashOk,
    registryPublicKeyOk,
    registryStatusOk,
    errors,
    warnings
  };
}
