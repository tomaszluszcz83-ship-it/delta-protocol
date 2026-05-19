import { verifyIntentBinding } from "../src/intentVerifier.js";

function argValue(flag: string): string | null {
  const index = process.argv.indexOf(flag);
  if (index === -1) return null;
  return process.argv[index + 1] ?? null;
}

const record = argValue("--record") ?? process.argv[2] ?? null;
const intent = argValue("--intent") ?? process.argv[3] ?? null;

if (!record || !intent) {
  console.error("usage: npm run verify-intent -- --record path/to/delta-record.json --intent path/to/intent-attestation.json");
  process.exit(2);
}

const result = verifyIntentBinding(record, intent);

console.log(`DELTA_TS_INTENT_VERIFY_OK=${result.ok ? "True" : "False"}`);
console.log(`DELTA_TS_INTENT_PROFILE=${result.profile}`);
console.log(`DELTA_TS_INTENT_RECORD=${result.recordPath}`);
console.log(`DELTA_TS_INTENT_ATTESTATION=${result.intentPath}`);
console.log(`DELTA_TS_INTENT_FILE_OK=${result.intentFileOk ? "True" : "False"}`);
console.log(`DELTA_TS_INTENT_RECORD_FILE_OK=${result.recordFileOk ? "True" : "False"}`);
console.log(`DELTA_TS_INTENT_RECORD_HASH_BINDING_OK=${result.recordHashBindingOk ? "True" : "False"}`);

if (result.recordHashBindingMethod) {
  console.log(`DELTA_TS_INTENT_RECORD_HASH_BINDING_METHOD=${result.recordHashBindingMethod}`);
}

if (result.declaredRecordHash) {
  console.log(`DELTA_TS_INTENT_DECLARED_RECORD_HASH=${result.declaredRecordHash}`);
}

if (result.computedRecordFileHash) {
  console.log(`DELTA_TS_INTENT_COMPUTED_RECORD_FILE_HASH=${result.computedRecordFileHash}`);
}

if (result.computedRecordCanonicalHash) {
  console.log(`DELTA_TS_INTENT_COMPUTED_RECORD_CANONICAL_HASH=${result.computedRecordCanonicalHash}`);
}

if (result.intentStatus) {
  console.log(`DELTA_TS_INTENT_STATUS=${result.intentStatus}`);
}

if (result.intentProfile) {
  console.log(`DELTA_TS_INTENT_ATTESTATION_PROFILE=${result.intentProfile}`);
}

console.log(`DELTA_TS_INTENT_SIGNATURE_PRESENT=${result.signaturePresent ? "True" : "False"}`);
console.log(`DELTA_TS_INTENT_SIGNATURE_VERIFICATION_STATUS=${result.signatureVerificationStatus}`);

for (const warning of result.warnings) {
  console.log(`DELTA_TS_INTENT_WARNING=${warning}`);
}

for (const error of result.errors) {
  console.log(`DELTA_TS_INTENT_REASON=${error}`);
}

process.exit(result.ok ? 0 : 1);
