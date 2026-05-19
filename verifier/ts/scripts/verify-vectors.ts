import { readFileSync } from "node:fs";
import { canonicalizeJsonText, canonicalizeJsonValue, parseStrictJson, type JsonValue } from "../src/canonicalJson.js";
import { sha256HexBytes } from "../src/hash.js";

type AnyObject = Record<string, unknown>;

function sanitizeId(value: unknown, fallback: string): string {
  const raw = String(value ?? fallback).toUpperCase();
  return raw.replace(/[^A-Z0-9]+/g, "_").replace(/^_+|_+$/g, "") || fallback;
}

function asObject(value: unknown): AnyObject {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }
  return value as AnyObject;
}

function getFirst(obj: AnyObject, names: string[]): unknown {
  for (const name of names) {
    if (name in obj) return obj[name];
  }
  return undefined;
}

function vectorArray(root: AnyObject, names: string[]): AnyObject[] {
  for (const name of names) {
    const value = root[name];
    if (Array.isArray(value)) return value.map(asObject);
  }
  return [];
}

function normalizeHash(value: unknown): string | null {
  if (typeof value !== "string") return null;
  return value.startsWith("sha256:") ? value.slice("sha256:".length) : value;
}

function canonicalFromVectorInput(value: unknown): string {
  if (typeof value === "string") {
    return canonicalizeJsonText(value);
  }
  return canonicalizeJsonValue(value as JsonValue);
}

function verifyValidVector(vector: AnyObject, index: number): boolean {
  const id = sanitizeId(getFirst(vector, ["id", "name", "vector_id"]), `VECTOR_${index + 1}`);
  const raw = getFirst(vector, ["raw_json", "raw", "input_json", "input", "json"]);
  const expectedCanonical = getFirst(vector, ["canonical_json", "canonical", "expected_canonical_json", "expected_canonical"]);
  const expectedHash = normalizeHash(getFirst(vector, ["expected_sha256", "sha256", "hash", "canonical_sha256", "expected_hash"]));

  if (raw === undefined) {
    console.log(`DELTA_TS_JCS_VECTOR_${id}_OK=False`);
    console.log(`DELTA_TS_JCS_VECTOR_${id}_REASON=missing_raw_input`);
    return false;
  }

  try {
    const canonical = canonicalFromVectorInput(raw);
    const hash = sha256HexBytes(canonical);

    let ok = true;

    if (typeof expectedCanonical === "string" && canonical !== expectedCanonical) {
      ok = false;
      console.log(`DELTA_TS_JCS_VECTOR_${id}_REASON=canonical_mismatch`);
    }

    if (expectedHash !== null && hash !== expectedHash) {
      ok = false;
      console.log(`DELTA_TS_JCS_VECTOR_${id}_REASON=hash_mismatch`);
      console.log(`DELTA_TS_JCS_VECTOR_${id}_EXPECTED_SHA256=${expectedHash}`);
      console.log(`DELTA_TS_JCS_VECTOR_${id}_ACTUAL_SHA256=${hash}`);
    }

    if (expectedCanonical === undefined && expectedHash === null) {
      ok = false;
      console.log(`DELTA_TS_JCS_VECTOR_${id}_REASON=missing_expected_canonical_or_hash`);
    }

    console.log(`DELTA_TS_JCS_VECTOR_${id}_OK=${ok ? "True" : "False"}`);
    return ok;
  } catch (err) {
    console.log(`DELTA_TS_JCS_VECTOR_${id}_OK=False`);
    console.log(`DELTA_TS_JCS_VECTOR_${id}_REASON=${err instanceof Error ? err.name : "unknown_error"}`);
    return false;
  }
}

function verifyInvalidVector(vector: AnyObject, index: number): boolean {
  const id = sanitizeId(getFirst(vector, ["id", "name", "vector_id"]), `INVALID_${index + 1}`);
  const raw = getFirst(vector, ["raw_json", "raw", "input_json", "input", "json"]);

  if (raw === undefined) {
    console.log(`DELTA_TS_JCS_INVALID_VECTOR_${id}_REJECTED=False`);
    console.log(`DELTA_TS_JCS_INVALID_VECTOR_${id}_REASON=missing_raw_input`);
    return false;
  }

  try {
    if (typeof raw === "string") {
      canonicalizeJsonText(raw);
    } else {
      canonicalizeJsonValue(raw as JsonValue);
    }
    console.log(`DELTA_TS_JCS_INVALID_VECTOR_${id}_REJECTED=False`);
    console.log(`DELTA_TS_JCS_INVALID_VECTOR_${id}_REASON=unexpected_accept`);
    return false;
  } catch (err) {
    console.log(`DELTA_TS_JCS_INVALID_VECTOR_${id}_REJECTED=True`);
    console.log(`DELTA_TS_JCS_INVALID_VECTOR_${id}_REASON=${err instanceof Error ? err.name : "unknown_error"}`);
    return true;
  }
}

const vectorsPath = process.argv[2] ?? "../../tests/vectors/canonical-json/vectors.json";
const root = asObject(JSON.parse(readFileSync(vectorsPath, "utf-8")));

const valid = vectorArray(root, ["valid_vectors", "valid", "vectors", "canonical_vectors"]);
const invalid = vectorArray(root, ["invalid_vectors", "invalid", "rejected_vectors"]);

let ok = true;

if (valid.length === 0) {
  console.log("DELTA_TS_JCS_VALID_VECTOR_SET_FOUND=False");
  ok = false;
} else {
  console.log("DELTA_TS_JCS_VALID_VECTOR_SET_FOUND=True");
}

valid.forEach((vector, index) => {
  ok = verifyValidVector(vector, index) && ok;
});

invalid.forEach((vector, index) => {
  ok = verifyInvalidVector(vector, index) && ok;
});

console.log("DELTA_TS_PROFILE=delta_typescript_verifier_l0_l1_v2_9_0");
console.log(`DELTA_TS_VERIFY_OK=${ok ? "True" : "False"}`);

process.exit(ok ? 0 : 1);
