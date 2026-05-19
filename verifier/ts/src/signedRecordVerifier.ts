import { canonicalizeJsonValue, type JsonObject, type JsonValue } from "./canonicalJson.js";
import { sha256PrefixedBytes } from "./hash.js";
import {
  decodeBytes,
  publicKeyHash,
  verifyEd25519Signature
} from "./ed25519Verifier.js";

export interface SignedRecordVerificationResult {
  ok: boolean;
  errors: string[];
  declaredRecordHash: string | null;
  computedRecordHash: string;
  recordHashMatches: boolean;
  publicKeyHashMatches: boolean | null;
  signatureOk: boolean;
}

const SIGNATURE_METADATA_FIELDS = [
  "record_hash",
  "signature",
  "ed25519_signature",
  "public_key",
  "signer_public_key",
  "public_key_hash",
  "signer_public_key_hash",
  "signature_algorithm",
  "signature_profile",
  "signature_target",
  "signature_status",
  "signature_verified",
  "signature_body_hash"
];

function deepCloneJson<T extends JsonValue>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function getStringField(record: JsonObject, names: string[]): string | null {
  for (const name of names) {
    const value = record[name];
    if (typeof value === "string" && value.length > 0) {
      return value;
    }
  }
  return null;
}

export function computeSignedRecordHash(record: JsonObject): string {
  const copy = deepCloneJson(record as JsonValue) as JsonObject;

  for (const field of SIGNATURE_METADATA_FIELDS) {
    delete copy[field];
  }

  return sha256PrefixedBytes(canonicalizeJsonValue(copy as JsonValue));
}

export async function verifySignedRecord(record: JsonObject): Promise<SignedRecordVerificationResult> {
  const errors: string[] = [];

  const declaredRecordHash = getStringField(record, ["record_hash"]);
  const signatureValue = getStringField(record, ["signature", "ed25519_signature"]);
  const publicKeyValue = getStringField(record, ["public_key", "signer_public_key"]);
  const declaredPublicKeyHash = getStringField(record, ["public_key_hash", "signer_public_key_hash"]);

  if (!declaredRecordHash) errors.push("missing_record_hash");
  if (!signatureValue) errors.push("missing_signature");
  if (!publicKeyValue) errors.push("missing_public_key");

  const computedRecordHash = computeSignedRecordHash(record);
  const recordHashMatches = declaredRecordHash === computedRecordHash;

  if (declaredRecordHash && !recordHashMatches) {
    errors.push("record_hash_mismatch");
  }

  let publicKeyHashMatches: boolean | null = null;
  let signatureOk = false;

  if (signatureValue && publicKeyValue && declaredRecordHash) {
    try {
      const publicKey = decodeBytes(publicKeyValue, "ed25519");
      const signature = decodeBytes(signatureValue, "ed25519");
      const actualPublicKeyHash = publicKeyHash(publicKey);

      if (declaredPublicKeyHash) {
        publicKeyHashMatches = declaredPublicKeyHash === actualPublicKeyHash;
        if (!publicKeyHashMatches) {
          errors.push("public_key_hash_mismatch");
        }
      }

      signatureOk = verifyEd25519Signature(
        signature,
        Uint8Array.from(Buffer.from(declaredRecordHash, "utf-8")),
        publicKey
      );

      if (!signatureOk) {
        errors.push("signature_invalid");
      }
    } catch (err) {
      errors.push(err instanceof Error ? `${err.name}:${err.message}` : "signature_verification_error");
    }
  }

  return {
    ok: errors.length === 0 && recordHashMatches && signatureOk,
    errors,
    declaredRecordHash,
    computedRecordHash,
    recordHashMatches,
    publicKeyHashMatches,
    signatureOk
  };
}
