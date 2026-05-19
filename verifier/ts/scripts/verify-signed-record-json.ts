import { readFileSync } from "node:fs";
import {
  argValue,
  internalErrorResult,
  printJson,
  usageResult,
  verificationResult
} from "../src/cliResult.js";
import { parseStrictJson, type JsonObject } from "../src/canonicalJson.js";
import { verifySignedRecord } from "../src/signedRecordVerifier.js";

const command = "verify-signed-record-json";
const record = argValue("--record") ?? process.argv[2] ?? null;

if (!record) {
  const result = usageResult(command, "usage: npm run verify-signed-record-json -- --record path/to/signed-record.json");
  printJson(result);
  process.exit(result.code);
}

try {
  const value = parseStrictJson(readFileSync(record, "utf-8"));

  if (!value || typeof value !== "object" || Array.isArray(value)) {
    const result = verificationResult(command, false, null, ["record_not_object"], []);
    printJson(result);
    process.exit(result.code);
  }

  const signedRecordResult = await verifySignedRecord(value as JsonObject);
  const result = verificationResult(
    command,
    signedRecordResult.ok,
    signedRecordResult,
    signedRecordResult.errors,
    []
  );
  printJson(result);
  process.exit(result.code);
} catch (err) {
  const result = internalErrorResult(command, err);
  printJson(result);
  process.exit(result.code);
}
