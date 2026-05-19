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

if (!record || !intent) {
  const result = usageResult(
    command,
    "usage: npm run verify-intent-json -- --record path/to/delta-record.json --intent path/to/intent-attestation.json"
  );
  printJson(result);
  process.exit(result.code);
}

try {
  const intentResult = verifyIntentBinding(record, intent);
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
