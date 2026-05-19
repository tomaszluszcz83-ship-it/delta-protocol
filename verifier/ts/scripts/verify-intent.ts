import { verifyIntentBinding } from "../src/intentVerifier.js";

function argValue(flag: string): string | null {
  const index = process.argv.indexOf(flag);
  if (index === -1) return null;
  return process.argv[index + 1] ?? null;
}

const record = argValue("--record") ?? process.argv[2] ?? null;
const intent = argValue("--intent") ?? process.argv[3] ?? null;
const signature = argValue("--signature");
const registry = argValue("--registry");
const policy = argValue("--policy");
const now = argValue("--now");

if (!record || !intent) {
  console.error("usage: npm run verify-intent -- --record path/to/delta-record.json --intent path/to/intent-attestation.json [--signature path/to/intent-signature.json] [--registry path/to/intent-registry.json] [--policy path/to/intent-policy.json] [--now 2026-01-01T00:00:00Z]");
  process.exit(2);
}

const result = verifyIntentBinding(record, intent, {
  signaturePath: signature ?? undefined,
  registryPath: registry ?? undefined,
  policyPath: policy ?? undefined,
  now
});

console.log(`DELTA_TS_INTENT_VERIFY_OK=${result.ok ? "True" : "False"}`);
console.log(`DELTA_TS_INTENT_PROFILE=${result.profile}`);
console.log(`DELTA_TS_INTENT_RECORD=${result.recordPath}`);
console.log(`DELTA_TS_INTENT_ATTESTATION=${result.intentPath}`);

if (result.signaturePath) console.log(`DELTA_TS_INTENT_SIGNATURE=${result.signaturePath}`);
if (result.registryPath) console.log(`DELTA_TS_INTENT_REGISTRY=${result.registryPath}`);
if (result.policyPath) console.log(`DELTA_TS_INTENT_POLICY=${result.policyPath}`);

console.log(`DELTA_TS_INTENT_FILE_OK=${result.intentFileOk ? "True" : "False"}`);
console.log(`DELTA_TS_INTENT_RECORD_FILE_OK=${result.recordFileOk ? "True" : "False"}`);
console.log(`DELTA_TS_INTENT_RECORD_HASH_BINDING_OK=${result.recordHashBindingOk ? "True" : "False"}`);

if (result.recordHashBindingMethod) console.log(`DELTA_TS_INTENT_RECORD_HASH_BINDING_METHOD=${result.recordHashBindingMethod}`);
if (result.intentPolicyId) console.log(`DELTA_TS_INTENT_POLICY_ID=${result.intentPolicyId}`);
if (result.intentDeadline) console.log(`DELTA_TS_INTENT_DEADLINE=${result.intentDeadline}`);

console.log(`DELTA_TS_INTENT_SIGNATURE_VERIFICATION_STATUS=${result.signatureVerificationStatus}`);
console.log(`DELTA_TS_INTENT_REGISTRY_VERIFICATION_STATUS=${result.registryVerificationStatus}`);
console.log(`DELTA_TS_INTENT_POLICY_VERIFICATION_STATUS=${result.policyVerificationStatus}`);

if (result.signatureFileOk !== null) console.log(`DELTA_TS_INTENT_SIGNATURE_FILE_OK=${result.signatureFileOk ? "True" : "False"}`);
if (result.intentHashBindingOk !== null) console.log(`DELTA_TS_INTENT_SIGNATURE_INTENT_HASH_BINDING_OK=${result.intentHashBindingOk ? "True" : "False"}`);
if (result.signatureBodyHashOk !== null) console.log(`DELTA_TS_INTENT_SIGNATURE_BODY_HASH_OK=${result.signatureBodyHashOk ? "True" : "False"}`);
if (result.publicKeyHashOk !== null) console.log(`DELTA_TS_INTENT_SIGNATURE_PUBLIC_KEY_HASH_OK=${result.publicKeyHashOk ? "True" : "False"}`);
if (result.signatureShapeOk !== null) console.log(`DELTA_TS_INTENT_SIGNATURE_SHAPE_OK=${result.signatureShapeOk ? "True" : "False"}`);
if (result.signatureOk !== null) console.log(`DELTA_TS_INTENT_SIGNATURE_OK=${result.signatureOk ? "True" : "False"}`);

if (result.registryResult) {
  console.log(`DELTA_TS_INTENT_REGISTRY_FILE_OK=${result.registryResult.registryFileOk ? "True" : "False"}`);
  console.log(`DELTA_TS_INTENT_REGISTRY_ENTRY_FOUND=${result.registryResult.registryEntryFound ? "True" : "False"}`);
  if (result.registryResult.registryPublicKeyHashOk !== null) console.log(`DELTA_TS_INTENT_REGISTRY_PUBLIC_KEY_HASH_OK=${result.registryResult.registryPublicKeyHashOk ? "True" : "False"}`);
  if (result.registryResult.registryPublicKeyOk !== null) console.log(`DELTA_TS_INTENT_REGISTRY_PUBLIC_KEY_OK=${result.registryResult.registryPublicKeyOk ? "True" : "False"}`);
  if (result.registryResult.registryStatusOk !== null) console.log(`DELTA_TS_INTENT_REGISTRY_STATUS_OK=${result.registryResult.registryStatusOk ? "True" : "False"}`);
}

if (result.policyResult) {
  console.log(`DELTA_TS_INTENT_POLICY_FILE_OK=${result.policyResult.policyFileOk ? "True" : "False"}`);
  if (result.policyResult.policyIdOk !== null) console.log(`DELTA_TS_INTENT_POLICY_ID_OK=${result.policyResult.policyIdOk ? "True" : "False"}`);
  if (result.policyResult.deadlineOk !== null) console.log(`DELTA_TS_INTENT_POLICY_DEADLINE_OK=${result.policyResult.deadlineOk ? "True" : "False"}`);
  if (result.policyResult.policyStatusOk !== null) console.log(`DELTA_TS_INTENT_POLICY_STATUS_OK=${result.policyResult.policyStatusOk ? "True" : "False"}`);
  if (result.policyResult.effectiveDeadline) console.log(`DELTA_TS_INTENT_POLICY_EFFECTIVE_DEADLINE=${result.policyResult.effectiveDeadline}`);
  console.log(`DELTA_TS_INTENT_POLICY_NOW=${result.policyResult.now}`);
}

for (const warning of result.warnings) console.log(`DELTA_TS_INTENT_WARNING=${warning}`);
for (const error of result.errors) console.log(`DELTA_TS_INTENT_REASON=${error}`);

process.exit(result.ok ? 0 : 1);
