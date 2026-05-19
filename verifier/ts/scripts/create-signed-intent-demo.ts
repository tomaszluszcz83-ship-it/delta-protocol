import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { canonicalizeJsonValue, type JsonObject, type JsonValue } from "../src/canonicalJson.js";

function argValue(flag: string): string | null {
  const index = process.argv.indexOf(flag);
  if (index === -1) return null;
  return process.argv[index + 1] ?? null;
}

function sha256Prefixed(data: Buffer | string): string {
  return `sha256:${createHash("sha256").update(data).digest("hex")}`;
}

function base64url(data: Buffer | Uint8Array): string {
  return Buffer.from(data).toString("base64url");
}

const outDir = argValue("--out-dir") ?? process.argv[2] ?? null;

if (!outDir) {
  console.error("usage: npm run create-signed-intent-demo -- --out-dir path/to/output-directory");
  process.exit(2);
}

mkdirSync(outDir, { recursive: true });

const recordPath = join(outDir, "delta-record.json");
const intentPath = join(outDir, "intent-attestation.json");
const signaturePath = join(outDir, "intent-signature.json");

const record = {
  before_state: { demo: "before" },
  action: { type: "typescript-detached-intent-signature-test" },
  after_state: { demo: "after" },
  evidence: { test: true },
  verification: { status: "demo" }
};

const recordText = `${JSON.stringify(record, null, 2)}\n`;
writeFileSync(recordPath, recordText, "utf-8");

const recordHash = sha256Prefixed(Buffer.from(recordText, "utf-8"));

const intent: JsonObject = {
  profile: "delta_intent_attestation_test_v2_12_1",
  status: "unsigned_draft",
  purpose: "TypeScript detached intent signature verification test",
  record_hash: recordHash,
  security_boundary: "record_hash_binding_and_detached_signature_only_not_legal_approval"
};

const intentText = `${JSON.stringify(intent, null, 2)}\n`;
writeFileSync(intentPath, intentText, "utf-8");

const intentHash = sha256Prefixed(canonicalizeJsonValue(intent as JsonValue));

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const publicKeyDer = publicKey.export({ type: "spki", format: "der" });
const rawPublicKey = publicKeyDer.subarray(publicKeyDer.length - 32);

const publicKeyText = `ed25519:${base64url(rawPublicKey)}`;
const publicKeyHash = sha256Prefixed(publicKeyText);

const signatureBody: JsonObject = {
  type: "delta_intent_signature_body",
  signature_profile: "delta_intent_ed25519_detached_v2_12_1",
  intent: {
    hash_alg: "sha256",
    intent_hash: intentHash,
    path_hint: intentPath
  },
  record: {
    hash_alg: "sha256",
    record_hash: recordHash,
    path_hint: recordPath
  },
  signer: {
    label: "typescript-local-demo-signer",
    public_key: publicKeyText,
    public_key_hash: publicKeyHash
  },
  security_boundary: {
    does_not_prove_legal_identity: true,
    does_not_prove_signer_authority: true,
    does_not_prove_policy_compliance: true,
    does_not_replace_registry_trust: true
  }
};

const signatureBodyCanonical = canonicalizeJsonValue(signatureBody as JsonValue);
const signatureBodyHash = sha256Prefixed(signatureBodyCanonical);
const signatureBytes = sign(null, Buffer.from(signatureBodyCanonical, "utf-8"), privateKey);

const signatureObject = {
  type: "delta_intent_detached_signature",
  signature_profile: "delta_intent_ed25519_detached_v2_12_1",
  signature_body_hash: signatureBodyHash,
  signature_body: signatureBody,
  signature: {
    alg: "ed25519",
    public_key: publicKeyText,
    public_key_hash: publicKeyHash,
    signature: `ed25519sig:${base64url(signatureBytes)}`,
    target: "canonical_json(signature_body)",
    target_hash: signatureBodyHash
  }
};

writeFileSync(signaturePath, `${JSON.stringify(signatureObject, null, 2)}\n`, "utf-8");

console.log("DELTA_TS_SIGNED_INTENT_DEMO_CREATE_OK=True");
console.log(`DELTA_TS_SIGNED_INTENT_RECORD=${recordPath}`);
console.log(`DELTA_TS_SIGNED_INTENT_ATTESTATION=${intentPath}`);
console.log(`DELTA_TS_SIGNED_INTENT_SIGNATURE=${signaturePath}`);
console.log(`DELTA_TS_SIGNED_INTENT_RECORD_HASH=${recordHash}`);
console.log(`DELTA_TS_SIGNED_INTENT_INTENT_HASH=${intentHash}`);
console.log(`DELTA_TS_SIGNED_INTENT_SIGNATURE_BODY_HASH=${signatureBodyHash}`);
console.log(`DELTA_TS_SIGNED_INTENT_PUBLIC_KEY_HASH=${publicKeyHash}`);
