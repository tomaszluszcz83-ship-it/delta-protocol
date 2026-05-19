import { readFileSync } from "node:fs";
import { parseStrictJson, type JsonObject } from "./canonicalJson.js";

export const INTENT_POLICY_PROFILE = "delta_typescript_intent_policy_deadline_v2_12_3";

export type IntentPolicyVerificationStatus = "NOT_PROVIDED" | "SATISFIED" | "INVALID";

export interface IntentPolicyVerificationInput {
  policyPath: string;
  intentPolicyId: string | null;
  intentDeadline: string | null;
  now?: string | null | undefined;
}

export interface IntentPolicyVerificationResult {
  ok: boolean;
  profile: string;
  policyPath: string;
  policyFileOk: boolean;
  policyVerificationStatus: IntentPolicyVerificationStatus;
  intentPolicyId: string | null;
  policyId: string | null;
  policyIdOk: boolean | null;
  intentDeadline: string | null;
  policyDeadline: string | null;
  effectiveDeadline: string | null;
  now: string;
  deadlineOk: boolean | null;
  policyStatus: string | null;
  policyStatusOk: boolean | null;
  errors: string[];
  warnings: string[];
}

export class DeltaIntentPolicyVerifierError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DeltaIntentPolicyVerifierError";
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

function readJsonObject(path: string): JsonObject {
  const parsed = parseStrictJson(readFileSync(path, "utf-8"));
  if (!isObject(parsed)) {
    throw new DeltaIntentPolicyVerifierError(`policy JSON is not an object: ${path}`);
  }
  return parsed as JsonObject;
}

function parseIsoDate(value: string): number | null {
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) ? timestamp : null;
}

function policyStatusIsActive(status: string | null): boolean {
  if (!status) return true;
  return ["active", "valid", "enabled", "enforced"].includes(status.toLowerCase());
}

export function verifyIntentPolicy(input: IntentPolicyVerificationInput): IntentPolicyVerificationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  let policyFileOk = false;
  let policy: JsonObject | null = null;

  try {
    policy = readJsonObject(input.policyPath);
    policyFileOk = true;
  } catch (err) {
    errors.push(`intent_policy_file_error:${err instanceof Error ? err.message : "unknown"}`);
  }

  const policyId =
    getString(policy, "policy_id") ??
    getString(policy, "intent_policy_id") ??
    getString(policy, "id");

  const policyDeadline =
    getString(policy, "deadline") ??
    getString(policy, "intent_deadline") ??
    getString(policy, "not_after") ??
    getString(policy, "valid_until");

  const policyStatus =
    getString(policy, "status") ??
    getString(policy, "policy_status");

  let policyIdOk: boolean | null = null;

  if (!input.intentPolicyId) {
    errors.push("intent_policy_id_missing");
  }

  if (!policyId) {
    errors.push("policy_id_missing");
  }

  if (input.intentPolicyId && policyId) {
    policyIdOk = input.intentPolicyId === policyId;
    if (!policyIdOk) {
      errors.push(`intent_policy_id_mismatch:intent=${input.intentPolicyId}:policy=${policyId}`);
    }
  }

  const effectiveDeadline = input.intentDeadline ?? policyDeadline ?? null;
  const now = input.now ?? new Date().toISOString();

  let deadlineOk: boolean | null = null;

  if (!effectiveDeadline) {
    errors.push("intent_policy_deadline_missing");
  } else {
    const deadlineTs = parseIsoDate(effectiveDeadline);
    const nowTs = parseIsoDate(now);

    if (deadlineTs === null) {
      errors.push(`intent_policy_deadline_invalid:${effectiveDeadline}`);
    } else if (nowTs === null) {
      errors.push(`intent_policy_now_invalid:${now}`);
    } else {
      deadlineOk = nowTs <= deadlineTs;
      if (!deadlineOk) {
        errors.push(`intent_policy_deadline_expired:deadline=${effectiveDeadline}:now=${now}`);
      }
    }
  }

  const policyStatusOk = policy ? policyStatusIsActive(policyStatus) : false;

  if (policy && !policyStatusOk) {
    errors.push(`intent_policy_status_not_active:status=${policyStatus ?? "null"}`);
  }

  if (input.intentDeadline && policyDeadline && input.intentDeadline !== policyDeadline) {
    warnings.push(`intent_policy_deadline_differs:intent=${input.intentDeadline}:policy=${policyDeadline}`);
  }

  const ok =
    policyFileOk &&
    policyIdOk === true &&
    deadlineOk === true &&
    policyStatusOk === true &&
    errors.length === 0;

  return {
    ok,
    profile: INTENT_POLICY_PROFILE,
    policyPath: input.policyPath,
    policyFileOk,
    policyVerificationStatus: ok ? "SATISFIED" : "INVALID",
    intentPolicyId: input.intentPolicyId,
    policyId,
    policyIdOk,
    intentDeadline: input.intentDeadline,
    policyDeadline,
    effectiveDeadline,
    now,
    deadlineOk,
    policyStatus,
    policyStatusOk,
    errors,
    warnings
  };
}
