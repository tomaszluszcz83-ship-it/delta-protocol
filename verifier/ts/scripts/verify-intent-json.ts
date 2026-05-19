import {
  argValue,
  internalErrorResult,
  printJson,
  usageResult,
  verificationResult
} from "../src/cliResult.js";
import { verifyIntentBinding } from "../src/intentVerifier.js";

const command = "verify-intent-json";
const record = argValue("--record") ?? process.argv[2] ?? null;
const intent = argValue("--intent") ?? process.argv[3] ?? null;
const signature = argValue("--signature");
const registry = argValue("--registry");
const policy = argValue("--policy");
const now = argValue("--now");

if (!record || !intent) {
  const result = usageResult(
    command,
    "usage: npm run verify-intent-json -- --record path/to/delta-record.json --intent path/to/intent-attestation.json [--signature path/to/intent-signature.json] [--registry path/to/intent-registry.json] [--policy path/to/intent-policy.json] [--now 2026-01-01T00:00:00Z]"
  );
  printJson(result);
  process.exit(result.code);
}

try {
  const intentResult = verifyIntentBinding(record, intent, {
    signaturePath: signature ?? undefined,
    registryPath: registry ?? undefined,
    policyPath: policy ?? undefined,
    now
  });
  const result = verificationResult(
    command,
    intentResult.ok,
    intentResult,
    intentResult.errors,
    intentResult.warnings
  );
  printJson(result);
  process.exit(result.code);
} catch (err) {
  const result = internalErrorResult(command, err);
  printJson(result);
  process.exit(result.code);
}
