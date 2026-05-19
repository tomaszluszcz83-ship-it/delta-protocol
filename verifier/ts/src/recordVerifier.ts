import { canonicalizeJsonValue, type JsonObject, type JsonValue } from "./canonicalJson.js";
import { sha256PrefixedBytes } from "./hash.js";

export const REQUIRED_RECORD_FIELDS = [
  "before_state",
  "action",
  "after_state",
  "evidence",
  "verification",
  "record_hash"
] as const;

export interface BasicRecordVerificationResult {
  ok: boolean;
  missingFields: string[];
  declaredRecordHash: string | null;
  computedRecordHash: string;
  recordHashMatches: boolean;
}

function deepCloneJson<T extends JsonValue>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

export function verifyRequiredRecordFields(record: JsonObject): string[] {
  return REQUIRED_RECORD_FIELDS.filter((field) => !(field in record));
}

export function computeBasicRecordHash(record: JsonObject): string {
  const copy = deepCloneJson(record);
  delete (copy as JsonObject).record_hash;
  return sha256PrefixedBytes(canonicalizeJsonValue(copy));
}

export function verifyBasicRecord(record: JsonObject): BasicRecordVerificationResult {
  const missingFields = verifyRequiredRecordFields(record);
  const declared = typeof record.record_hash === "string" ? record.record_hash : null;
  const computed = computeBasicRecordHash(record);
  const matches = declared === computed;

  return {
    ok: missingFields.length === 0 && declared !== null && matches,
    missingFields,
    declaredRecordHash: declared,
    computedRecordHash: computed,
    recordHashMatches: matches
  };
}
