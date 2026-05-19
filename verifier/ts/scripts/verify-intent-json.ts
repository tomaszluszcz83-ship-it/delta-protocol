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

if (!record || !intent) {
  const result = usageResult(
    command,
    "usage: npm run verify-intent-json -- --record path/to/delta-record.json --intent path/to/intent-attestation.json [--signature path/to/intent-signature.json] [--registry path/to/intent-registry.json]"
  );
  printJson(result);
  process.exit(result.code);
}

try {
  const intentResult = verifyIntentBinding(record, intent, signature ?? undefined, registry ?? undefined);
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
