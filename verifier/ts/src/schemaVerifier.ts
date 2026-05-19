import { readFileSync, readdirSync } from "node:fs";
import { createRequire } from "node:module";
import { join, resolve } from "node:path";
import type { ErrorObject, ValidateFunction } from "ajv";

const require = createRequire(import.meta.url);

const Ajv2020Module = require("ajv/dist/2020");
const Ajv2020Constructor = Ajv2020Module.default ?? Ajv2020Module;

const addFormatsModule = require("ajv-formats");
const addFormatsFunction = addFormatsModule.default ?? addFormatsModule;

type AjvLike = {
  addSchema: (schema: Record<string, unknown>, key?: string) => unknown;
  getSchema: (key: string) => ValidateFunction | undefined;
  compile: (schema: Record<string, unknown>) => ValidateFunction;
};

export interface LoadedSchema {
  path: string;
  schema: Record<string, unknown>;
  schemaId: string;
}

export interface SchemaValidationResult {
  ok: boolean;
  schemaId: string;
  schemaName: string;
  errors: string[];
}

export class DeltaSchemaVerifierError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DeltaSchemaVerifierError";
  }
}

export const SCHEMA_NAME_TO_FILE: Record<string, string> = {
  "delta-common": "delta-common.schema.json",
  "delta-record": "delta-record.schema.json",
  "intent-attestation": "intent-attestation.schema.json",
  "audit-package": "audit-package.schema.json",
  "publication-proof": "publication-proof.schema.json",
  "trust-ledger": "trust-ledger.schema.json",
  "wallet-proof": "wallet-proof.schema.json",
  "schema-registry": "schema-registry.json"
};

function isObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

export function readJsonObject(path: string): Record<string, unknown> {
  const data = JSON.parse(readFileSync(path, "utf-8")) as unknown;

  if (!isObject(data)) {
    throw new DeltaSchemaVerifierError(`JSON file is not an object: ${path}`);
  }

  return data;
}

export function loadSchemas(schemaDir: string): LoadedSchema[] {
  const root = resolve(schemaDir);
  const files = readdirSync(root)
    .filter((name) => name.endsWith(".json"))
    .sort();

  const loaded: LoadedSchema[] = [];

  for (const file of files) {
    const path = join(root, file);
    const schema = readJsonObject(path);
    const schemaId = schema.$id;

    if (typeof schemaId !== "string" || schemaId.length === 0) {
      throw new DeltaSchemaVerifierError(`schema missing $id: ${path}`);
    }

    loaded.push({ path, schema, schemaId });
  }

  return loaded;
}

export function createAjvWithSchemas(schemaDir: string): { ajv: AjvLike; schemas: LoadedSchema[] } {
  const ajv = new Ajv2020Constructor({
    allErrors: true,
    strict: false,
    validateSchema: true
  }) as AjvLike;

  addFormatsFunction(ajv);

  const schemas = loadSchemas(schemaDir);

  for (const loaded of schemas) {
    ajv.addSchema(loaded.schema, loaded.schemaId);
  }

  return { ajv, schemas };
}

export function getSchemaId(schemaDir: string, schemaName: string): string {
  const mapped = SCHEMA_NAME_TO_FILE[schemaName] ?? schemaName;
  const path = join(resolve(schemaDir), mapped);
  const schema = readJsonObject(path);
  const schemaId = schema.$id;

  if (typeof schemaId !== "string" || schemaId.length === 0) {
    throw new DeltaSchemaVerifierError(`schema missing $id: ${path}`);
  }

  return schemaId;
}

export function formatAjvErrors(errors: ErrorObject[] | null | undefined): string[] {
  if (!errors || errors.length === 0) {
    return [];
  }

  return errors.map((err) => {
    const path = err.instancePath || "/";
    return `${path}:${err.keyword}:${err.message ?? "schema validation error"}`;
  });
}

export function compileAllSchemas(schemaDir: string): LoadedSchema[] {
  const { ajv, schemas } = createAjvWithSchemas(schemaDir);

  for (const loaded of schemas) {
    const validate = ajv.getSchema(loaded.schemaId) ?? ajv.compile(loaded.schema);

    if (typeof validate !== "function") {
      throw new DeltaSchemaVerifierError(`could not compile schema: ${loaded.schemaId}`);
    }
  }

  return schemas;
}

export function validateJsonWithSchema(
  schemaDir: string,
  schemaName: string,
  jsonPath: string
): SchemaValidationResult {
  const { ajv } = createAjvWithSchemas(schemaDir);
  const schemaId = getSchemaId(schemaDir, schemaName);
  const validate = ajv.getSchema(schemaId);

  if (!validate) {
    throw new DeltaSchemaVerifierError(`schema not loaded: ${schemaId}`);
  }

  const value = JSON.parse(readFileSync(jsonPath, "utf-8")) as unknown;
  const ok = validate(value) === true;

  return {
    ok,
    schemaId,
    schemaName,
    errors: formatAjvErrors(validate.errors)
  };
}
