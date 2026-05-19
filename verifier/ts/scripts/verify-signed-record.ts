import { readFileSync } from "node:fs";
import { parseStrictJson, type JsonObject } from "../src/canonicalJson.js";
import { verifySignedRecord } from "../src/signedRecordVerifier.js";

function argValue(flag: string): string | null {
  const index = process.argv.indexOf(flag);
  if (index === -1) return null;
  return process.argv[index + 1] ?? null;
}

const recordPath = argValue("--record") ?? process.argv[2];

if (!recordPath) {
  console.error("usage: npm run verify-signed-record -- --record path/to/signed-record.json");
  process.exit(2);
}

const value = parseStrictJson(readFileSync(recordPath, "utf-8"));

if (!value || typeof value !== "object" || Array.isArray(value)) {
  console.log("DELTA_TS_SIGNED_RECORD_VERIFY_OK=False");
  console.log("DELTA_TS_SIGNED_RECORD_REASON=record_not_object");
  process.exit(1);
}

const result = await verifySignedRecord(value as JsonObject);

console.log(`DELTA_TS_SIGNED_RECORD_VERIFY_OK=${result.ok ? "True" : "False"}`);
console.log(`DELTA_TS_SIGNED_RECORD_HASH_OK=${result.recordHashMatches ? "True" : "False"}`);
console.log(`DELTA_TS_SIGNED_RECORD_SIGNATURE_OK=${result.signatureOk ? "True" : "False"}`);

if (result.publicKeyHashMatches !== null) {
  console.log(`DELTA_TS_SIGNED_RECORD_PUBLIC_KEY_HASH_OK=${result.publicKeyHashMatches ? "True" : "False"}`);
}

console.log(`DELTA_TS_SIGNED_RECORD_DECLARED_HASH=${result.declaredRecordHash ?? ""}`);
console.log(`DELTA_TS_SIGNED_RECORD_COMPUTED_HASH=${result.computedRecordHash}`);

for (const error of result.errors) {
  console.log(`DELTA_TS_SIGNED_RECORD_REASON=${error}`);
}

process.exit(result.ok ? 0 : 1);
