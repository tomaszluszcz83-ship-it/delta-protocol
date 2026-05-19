import { compileAllSchemas } from "../src/schemaVerifier.js";

const schemaDir = process.argv[2] ?? "../../schemas";

try {
  const schemas = compileAllSchemas(schemaDir);

  for (const schema of schemas) {
    console.log(`DELTA_TS_SCHEMA_COMPILE_OK=${schema.schemaId}`);
  }

  console.log("DELTA_TS_SCHEMA_PROFILE=delta_typescript_schema_validation_v2_9_1");
  console.log("DELTA_TS_SCHEMA_VERIFY_OK=True");
  process.exit(0);
} catch (err) {
  console.log("DELTA_TS_SCHEMA_VERIFY_OK=False");
  console.log(`DELTA_TS_SCHEMA_REASON=${err instanceof Error ? `${err.name}:${err.message}` : "unknown_error"}`);
  process.exit(1);
}
