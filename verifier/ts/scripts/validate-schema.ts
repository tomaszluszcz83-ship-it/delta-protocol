import { validateJsonWithSchema } from "../src/schemaVerifier.js";

function argValue(flag: string): string | null {
  const index = process.argv.indexOf(flag);
  if (index === -1) return null;
  return process.argv[index + 1] ?? null;
}

const schemaDir = argValue("--schemas") ?? "../../schemas";
const schema = argValue("--schema");
const file = argValue("--file");

if (!schema || !file) {
  console.error("usage: npm run validate-schema -- --schema delta-record --file path/to/file.json [--schemas ../../schemas]");
  process.exit(2);
}

try {
  const result = validateJsonWithSchema(schemaDir, schema, file);

  console.log(`DELTA_TS_SCHEMA_VALIDATE_OK=${result.ok ? "True" : "False"}`);
  console.log(`DELTA_TS_SCHEMA_NAME=${result.schemaName}`);
  console.log(`DELTA_TS_SCHEMA_ID=${result.schemaId}`);
  console.log(`DELTA_TS_SCHEMA_FILE=${file}`);

  for (const error of result.errors) {
    console.log(`DELTA_TS_SCHEMA_ERROR=${error}`);
  }

  process.exit(result.ok ? 0 : 1);
} catch (err) {
  console.log("DELTA_TS_SCHEMA_VALIDATE_OK=False");
  console.log(`DELTA_TS_SCHEMA_REASON=${err instanceof Error ? `${err.name}:${err.message}` : "unknown_error"}`);
  process.exit(1);
}
