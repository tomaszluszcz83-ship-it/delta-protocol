import * as ed from "https://cdn.jsdelivr.net/npm/@noble/ed25519@3.1.0/+esm";
import { sha256, sha512 } from "https://cdn.jsdelivr.net/npm/@noble/hashes@2.2.0/sha2.js";
import stableStringify from "https://cdn.jsdelivr.net/npm/fast-json-stable-stringify@2.1.0/+esm";

ed.hashes.sha512 = sha512;

const PROTOCOL_VERSION = "DELTA-0";
const encoder = new TextEncoder();

const els = {
  payloadInput: document.getElementById("payloadInput"),
  signatureInput: document.getElementById("signatureInput"),
  payloadFile: document.getElementById("payloadFile"),
  signatureFile: document.getElementById("signatureFile"),
  clearPayload: document.getElementById("clearPayload"),
  clearSignature: document.getElementById("clearSignature"),
  verifyPair: document.getElementById("verifyPair"),
  loadExample: document.getElementById("loadExample"),
  result: document.getElementById("result"),
  claimJson: document.getElementById("claimJson"),
  executorSigJson: document.getElementById("executorSigJson"),
  attestationJson: document.getElementById("attestationJson"),
  verifierSigJson: document.getElementById("verifierSigJson"),
  ledgerJson: document.getElementById("ledgerJson"),
  checkpointJson: document.getElementById("checkpointJson"),
  verifyBundle: document.getElementById("verifyBundle"),
  bundleOutput: document.getElementById("bundleOutput"),
};

function canonicalJSONString(obj) {
  const value = stableStringify(obj);
  if (typeof value !== "string") {
    throw new Error("Could not canonicalize JSON payload.");
  }
  return value;
}

function canonicalBytes(obj) {
  return encoder.encode(canonicalJSONString(obj));
}

function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function sha256Prefixed(bytes) {
  return "sha256:" + bytesToHex(sha256(bytes));
}

function hashObject(obj) {
  return sha256Prefixed(canonicalBytes(obj));
}

function b64urlToBytes(value) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error("Invalid base64url input.");
  }

  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (ch) => ch.charCodeAt(0));
}

function stripPrefix(label, value, prefix) {
  if (typeof value !== "string" || !value.startsWith(prefix)) {
    throw new Error(`${label} must start with ${prefix}`);
  }
  const raw = value.slice(prefix.length);
  if (!raw) {
    throw new Error(`${label} has an empty encoded value.`);
  }
  return raw;
}

function decodePublicKey(value) {
  const encoded = stripPrefix("public_key", value, "ed25519:");
  const bytes = b64urlToBytes(encoded);
  if (bytes.length !== 32) {
    throw new Error(`Ed25519 public key must be 32 bytes, got ${bytes.length}.`);
  }
  return bytes;
}

function decodeSignature(value) {
  const encoded = stripPrefix("signature", value, "ed25519sig:");
  const bytes = b64urlToBytes(encoded);
  if (bytes.length !== 64) {
    throw new Error(`Ed25519 signature must be 64 bytes, got ${bytes.length}.`);
  }
  return bytes;
}

function parseJson(text, label) {
  try {
    const obj = JSON.parse(text);
    if (!obj || typeof obj !== "object" || Array.isArray(obj)) {
      throw new Error(`${label} must be a JSON object.`);
    }
    return obj;
  } catch (err) {
    throw new Error(`${label} is not valid JSON: ${err.message}`);
  }
}

function requireEqual(label, actual, expected) {
  if (actual !== expected) {
    throw new Error(`${label} mismatch. Expected ${expected}, got ${actual}.`);
  }
}

function expectedSignatureBinding(payload, signature) {
  if (payload.type === "delta_claim") {
    return {
      role: "executor",
      targetType: "delta_claim",
      expectedPublicKey: payload.executor_pubkey,
      label: "Claim / Executor Signature",
    };
  }

  if (payload.type === "delta_attestation") {
    return {
      role: "verifier",
      targetType: "delta_attestation",
      expectedPublicKey: payload.verifier_pubkey,
      label: "Attestation / Verifier Signature",
    };
  }

  if (payload.type === "delta_signed_checkpoint") {
    return {
      role: "checkpoint_signer",
      targetType: "delta_signed_checkpoint",
      expectedPublicKey: null,
      label: "Checkpoint / Checkpoint Signer Signature",
    };
  }

  throw new Error(`Unsupported payload type: ${payload.type}`);
}

function assertSignatureEnvelope(signature) {
  requireEqual("signature.type", signature.type, "delta_signature");
  requireEqual("signature.protocol_version", signature.protocol_version, PROTOCOL_VERSION);

  if (signature.alg !== "Ed25519") {
    throw new Error(`Unsupported signature alg: ${signature.alg}`);
  }

  if (typeof signature.public_key !== "string") {
    throw new Error("signature.public_key is required.");
  }

  if (typeof signature.signature !== "string") {
    throw new Error("signature.signature is required.");
  }
}

function verifyPairObjects(payload, signature) {
  requireEqual("payload.protocol_version", payload.protocol_version, PROTOCOL_VERSION);
  assertSignatureEnvelope(signature);

  const binding = expectedSignatureBinding(payload, signature);

  requireEqual("signature.role", signature.role, binding.role);
  requireEqual("signature.target_type", signature.target_type, binding.targetType);

  if (binding.expectedPublicKey !== null) {
    requireEqual("signature.public_key", signature.public_key, binding.expectedPublicKey);
  }

  const payloadBytes = canonicalBytes(payload);
  const payloadHash = sha256Prefixed(payloadBytes);

  requireEqual("signature.target_hash", signature.target_hash, payloadHash);

  const publicKey = decodePublicKey(signature.public_key);
  const signatureBytes = decodeSignature(signature.signature);

  const ok = ed.verify(signatureBytes, payloadBytes, publicKey, { zip215: false });
  if (!ok) {
    throw new Error("Ed25519 verification failed over canonical JSON bytes.");
  }

  return {
    ok: true,
    pair: binding.label,
    targetHash: payloadHash,
    publicKey: signature.public_key,
  };
}

function setResult(kind, title, body) {
  els.result.className = `result ${kind}`;
  els.result.querySelector(".result-title").textContent = title;
  els.result.querySelector(".result-body").textContent = body;
}

async function readFileIntoTextarea(input, textarea) {
  const file = input.files?.[0];
  if (!file) return;
  textarea.value = await file.text();
}

els.payloadFile.addEventListener("change", () => readFileIntoTextarea(els.payloadFile, els.payloadInput));
els.signatureFile.addEventListener("change", () => readFileIntoTextarea(els.signatureFile, els.signatureInput));

els.clearPayload.addEventListener("click", () => {
  els.payloadInput.value = "";
  els.payloadFile.value = "";
});

els.clearSignature.addEventListener("click", () => {
  els.signatureInput.value = "";
  els.signatureFile.value = "";
});

els.verifyPair.addEventListener("click", () => {
  try {
    const payload = parseJson(els.payloadInput.value, "Payload JSON");
    const signature = parseJson(els.signatureInput.value, "Signature JSON");
    const verified = verifyPairObjects(payload, signature);

    setResult(
      "ok",
      "✅ DELTA VERIFIED",
      [
        `Pair: ${verified.pair}`,
        `Target hash: ${verified.targetHash}`,
        `Public key: ${verified.publicKey}`,
        "",
        "Signature verified over canonical JSON bytes.",
      ].join("\n")
    );
  } catch (err) {
    setResult("fail", "❌ FAILED", err.message);
  }
});

els.loadExample.addEventListener("click", () => {
  els.payloadInput.value = JSON.stringify({
    type: "delta_claim",
    protocol_version: "DELTA-0",
    created_at: "2026-05-16T00:00:00Z",
    executor_pubkey: "ed25519:PASTE_PUBLIC_KEY_HERE",
    before_hash: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
    action: "example action",
    after_hash: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
    evidence_hash: "sha256:3333333333333333333333333333333333333333333333333333333333333333"
  }, null, 2);

  els.signatureInput.value = JSON.stringify({
    type: "delta_signature",
    protocol_version: "DELTA-0",
    role: "executor",
    alg: "Ed25519",
    target_type: "delta_claim",
    target_hash: "sha256:PASTE_TARGET_HASH_HERE",
    public_key: "ed25519:PASTE_PUBLIC_KEY_HERE",
    signature: "ed25519sig:PASTE_SIGNATURE_HERE",
    signed_at: "2026-05-16T00:00:00Z"
  }, null, 2);

  setResult("warn", "Example shell loaded", "Replace placeholder values with real DELTA artifacts.");
});

function maybeParse(text, label, required = true) {
  if (!text.trim()) {
    if (required) throw new Error(`${label} is required.`);
    return null;
  }
  return parseJson(text, label);
}

function verifyBundleHashes() {
  const claim = maybeParse(els.claimJson.value, "claim.json");
  const executorSig = maybeParse(els.executorSigJson.value, "executor_signature.json");
  const attestation = maybeParse(els.attestationJson.value, "attestation.json");
  const verifierSig = maybeParse(els.verifierSigJson.value, "verifier_signature.json");
  const ledger = maybeParse(els.ledgerJson.value, "ledger_entry.json");
  const checkpoint = maybeParse(els.checkpointJson.value, "checkpoint.json", false);

  const claimPair = verifyPairObjects(claim, executorSig);
  const attestationPair = verifyPairObjects(attestation, verifierSig);

  const claimHash = hashObject(claim);
  const executorSigHash = hashObject(executorSig);
  const attestationHash = hashObject(attestation);
  const verifierSigHash = hashObject(verifierSig);
  const ledgerHash = hashObject(ledger);

  requireEqual("attestation.target_claim_hash", attestation.target_claim_hash, claimHash);
  requireEqual("attestation.target_executor_sig_hash", attestation.target_executor_sig_hash, executorSigHash);
  requireEqual("attestation.evidence_hash", attestation.evidence_hash, claim.evidence_hash);

  requireEqual("ledger.type", ledger.type, "delta_ledger_entry");
  requireEqual("ledger.protocol_version", ledger.protocol_version, PROTOCOL_VERSION);
  requireEqual("ledger.claim_hash", ledger.claim_hash, claimHash);
  requireEqual("ledger.executor_sig_hash", ledger.executor_sig_hash, executorSigHash);
  requireEqual("ledger.attestation_hash", ledger.attestation_hash, attestationHash);
  requireEqual("ledger.verifier_sig_hash", ledger.verifier_sig_hash, verifierSigHash);

  const lines = [
    "DELTA BUNDLE HASHES: OK",
    "",
    `claim_hash: ${claimHash}`,
    `executor_sig_hash: ${executorSigHash}`,
    `attestation_hash: ${attestationHash}`,
    `verifier_sig_hash: ${verifierSigHash}`,
    `ledger_entry_hash: ${ledgerHash}`,
    "",
    `Pair 1: ${claimPair.pair}`,
    `Pair 2: ${attestationPair.pair}`,
  ];

  if (checkpoint) {
    requireEqual("checkpoint.type", checkpoint.type, "delta_signed_checkpoint");
    requireEqual("checkpoint.protocol_version", checkpoint.protocol_version, PROTOCOL_VERSION);
    requireEqual("checkpoint.head_entry_hash", checkpoint.head_entry_hash, ledgerHash);
    lines.push(`checkpoint_hash: ${hashObject(checkpoint)}`);
    lines.push("checkpoint.head_entry_hash matches ledger_entry_hash");
  }

  return lines.join("\n");
}

els.verifyBundle.addEventListener("click", () => {
  try {
    els.bundleOutput.textContent = verifyBundleHashes();
  } catch (err) {
    els.bundleOutput.textContent = `DELTA BUNDLE HASHES: FAILED\n\n${err.message}`;
  }
});
