import { mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { generateKeyPairSync, sign as nodeSign } from "node:crypto";
import { computeSignedRecordHash } from "../src/signedRecordVerifier.js";
import { encodeEd25519Hex, publicKeyHash } from "../src/ed25519Verifier.js";
import type { JsonObject } from "../src/canonicalJson.js";

function argValue(flag: string): string | null {
  const index = process.argv.indexOf(flag);
  if (index === -1) return null;
  return process.argv[index + 1] ?? null;
}

function rawPublicKeyFromSpkiDer(spki: Buffer): Uint8Array {
  const prefix = Buffer.from("302a300506032b6570032100", "hex");
  if (spki.length !== prefix.length + 32 || !spki.subarray(0, prefix.length).equals(prefix)) {
    throw new Error("unexpected Ed25519 SPKI public key shape");
  }
  return Uint8Array.from(spki.subarray(prefix.length));
}

const out = argValue("--out") ?? ".delta/ts-signed-record-tests/R-292/signed-record.json";

const record: JsonObject = {
  before_state: {
    demo: "before"
  },
  action: {
    type: "typescript_ed25519_signed_record_demo",
    version: "v2.9.2"
  },
  after_state: {
    demo: "after"
  },
  evidence: {
    evidence_hashes: []
  },
  verification: {
    profile: "delta_ts_signed_record_demo_v2_9_2",
    note: "test vector generated locally; do not treat as production proof"
  },
  signature_algorithm: "ed25519",
  signature_profile: "delta_ts_ed25519_record_hash_v2_9_2"
};

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const publicKeyDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
const rawPublicKey = rawPublicKeyFromSpkiDer(publicKeyDer);

const recordHash = computeSignedRecordHash(record);
const signature = nodeSign(null, Buffer.from(recordHash, "utf-8"), privateKey);

record.record_hash = recordHash;
record.public_key = encodeEd25519Hex(rawPublicKey);
record.public_key_hash = publicKeyHash(rawPublicKey);
record.signature = encodeEd25519Hex(Uint8Array.from(signature));

mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, JSON.stringify(record, null, 2) + "\n", "utf-8");

console.log("DELTA_TS_SIGNED_RECORD_DEMO_CREATE_OK=True");
console.log(`DELTA_TS_SIGNED_RECORD_FILE=${out}`);
console.log(`DELTA_TS_SIGNED_RECORD_HASH=${recordHash}`);
console.log(`DELTA_TS_SIGNED_RECORD_PUBLIC_KEY_HASH=${record.public_key_hash}`);
