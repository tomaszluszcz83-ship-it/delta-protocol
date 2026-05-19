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

if (!record || !intent) {
  console.error("usage: npm run verify-intent -- --record path/to/delta-record.json --intent path/to/intent-attestation.json [--signature path/to/intent-signature.json] [--registry path/to/intent-registry.json]");
  process.exit(2);
}

const result = verifyIntentBinding(record, intent, signature ?? undefined, registry ?? undefined);

console.log(`DELTA_TS_INTENT_VERIFY_OK=${result.ok ? "True" : "False"}`);
console.log(`DELTA_TS_INTENT_PROFILE=${result.profile}`);
console.log(`DELTA_TS_INTENT_RECORD=${result.recordPath}`);
console.log(`DELTA_TS_INTENT_ATTESTATION=${result.intentPath}`);

if (result.signaturePath) {
  console.log(`DELTA_TS_INTENT_SIGNATURE=${result.signaturePath}`);
}

if (result.registryPath) {
  console.log(`DELTA_TS_INTENT_REGISTRY=${result.registryPath}`);
}

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

if (result.computedIntentCanonicalHash) {
  console.log(`DELTA_TS_INTENT_COMPUTED_INTENT_CANONICAL_HASH=${result.computedIntentCanonicalHash}`);
}

if (result.intentStatus) {
  console.log(`DELTA_TS_INTENT_STATUS=${result.intentStatus}`);
}

if (result.intentProfile) {
  console.log(`DELTA_TS_INTENT_ATTESTATION_PROFILE=${result.intentProfile}`);
}

console.log(`DELTA_TS_INTENT_SIGNATURE_VERIFICATION_STATUS=${result.signatureVerificationStatus}`);
console.log(`DELTA_TS_INTENT_REGISTRY_VERIFICATION_STATUS=${result.registryVerificationStatus}`);

if (result.signatureFileOk !== null) {
  console.log(`DELTA_TS_INTENT_SIGNATURE_FILE_OK=${result.signatureFileOk ? "True" : "False"}`);
}

if (result.intentHashBindingOk !== null) {
  console.log(`DELTA_TS_INTENT_SIGNATURE_INTENT_HASH_BINDING_OK=${result.intentHashBindingOk ? "True" : "False"}`);
}

if (result.signatureBodyHashOk !== null) {
  console.log(`DELTA_TS_INTENT_SIGNATURE_BODY_HASH_OK=${result.signatureBodyHashOk ? "True" : "False"}`);
}

if (result.publicKeyHashOk !== null) {
  console.log(`DELTA_TS_INTENT_SIGNATURE_PUBLIC_KEY_HASH_OK=${result.publicKeyHashOk ? "True" : "False"}`);
}

if (result.signatureShapeOk !== null) {
  console.log(`DELTA_TS_INTENT_SIGNATURE_SHAPE_OK=${result.signatureShapeOk ? "True" : "False"}`);
}

if (result.signatureOk !== null) {
  console.log(`DELTA_TS_INTENT_SIGNATURE_OK=${result.signatureOk ? "True" : "False"}`);
}

if (result.registryResult) {
  console.log(`DELTA_TS_INTENT_REGISTRY_FILE_OK=${result.registryResult.registryFileOk ? "True" : "False"}`);
  console.log(`DELTA_TS_INTENT_REGISTRY_ENTRY_FOUND=${result.registryResult.registryEntryFound ? "True" : "False"}`);

  if (result.registryResult.registryPublicKeyHashOk !== null) {
    console.log(`DELTA_TS_INTENT_REGISTRY_PUBLIC_KEY_HASH_OK=${result.registryResult.registryPublicKeyHashOk ? "True" : "False"}`);
  }

  if (result.registryResult.registryPublicKeyOk !== null) {
    console.log(`DELTA_TS_INTENT_REGISTRY_PUBLIC_KEY_OK=${result.registryResult.registryPublicKeyOk ? "True" : "False"}`);
  }

  if (result.registryResult.registryStatusOk !== null) {
    console.log(`DELTA_TS_INTENT_REGISTRY_STATUS_OK=${result.registryResult.registryStatusOk ? "True" : "False"}`);
  }
}

for (const warning of result.warnings) {
  console.log(`DELTA_TS_INTENT_WARNING=${warning}`);
}

for (const error of result.errors) {
  console.log(`DELTA_TS_INTENT_REASON=${error}`);
}

process.exit(result.ok ? 0 : 1);
