import { readFileSync } from "node:fs";
import { parseStrictJson, type JsonObject } from "../src/canonicalJson.js";
import { verifyBasicRecord } from "../src/recordVerifier.js";

const recordPath = process.argv[2];

if (!recordPath) {
  console.error("usage: npm run verify-record -- path/to/delta-record.json");
  process.exit(2);
}

const value = parseStrictJson(readFileSync(recordPath, "utf-8"));

if (!value || typeof value !== "object" || Array.isArray(value)) {
  console.log("DELTA_TS_RECORD_VERIFY_OK=False");
  console.log("DELTA_TS_RECORD_REASON=record_not_object");
  process.exit(1);
}

const result = verifyBasicRecord(value as JsonObject);

console.log(`DELTA_TS_RECORD_VERIFY_OK=${result.ok ? "True" : "False"}`);
console.log(`DELTA_TS_RECORD_HASH_MATCHES=${result.recordHashMatches ? "True" : "False"}`);
console.log(`DELTA_TS_RECORD_DECLARED_HASH=${result.declaredRecordHash ?? ""}`);
console.log(`DELTA_TS_RECORD_COMPUTED_HASH=${result.computedRecordHash}`);

if (result.missingFields.length > 0) {
  console.log(`DELTA_TS_RECORD_MISSING_FIELDS=${result.missingFields.join(",")}`);
}

process.exit(result.ok ? 0 : 1);
