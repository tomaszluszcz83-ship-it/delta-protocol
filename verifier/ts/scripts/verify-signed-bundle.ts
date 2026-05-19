import { verifySignedBundle } from "../src/signedBundleVerifier.js";

function argValue(flag: string): string | null {
  const index = process.argv.indexOf(flag);
  if (index === -1) return null;
  return process.argv[index + 1] ?? null;
}

const bundle = argValue("--bundle") ?? process.argv[2] ?? null;
const signature = argValue("--signature");
const publicKey = argValue("--public-key");

if (!bundle || !signature) {
  console.error("usage: npm run verify-signed-bundle -- --bundle path/to/file.delta --signature path/to/file.sig.json [--public-key ed25519:<hex>]");
  process.exit(2);
}

const result = await verifySignedBundle(bundle, signature, publicKey ?? undefined);

console.log(`DELTA_TS_SIGNED_BUNDLE_VERIFY_OK=${result.ok ? "True" : "False"}`);
console.log(`DELTA_TS_SIGNED_BUNDLE_PROFILE=${result.profile}`);
console.log(`DELTA_TS_SIGNED_BUNDLE_BUNDLE=${result.bundlePath}`);
console.log(`DELTA_TS_SIGNED_BUNDLE_SIGNATURE=${result.signaturePath}`);
console.log(`DELTA_TS_SIGNED_BUNDLE_BUNDLE_INTEGRITY_OK=${result.bundleIntegrityOk ? "True" : "False"}`);
console.log(`DELTA_TS_SIGNED_BUNDLE_SIGNATURE_FILE_OK=${result.signatureFileOk ? "True" : "False"}`);
console.log(`DELTA_TS_SIGNED_BUNDLE_BUNDLE_HASH_BINDING_OK=${result.bundleHashBindingOk ? "True" : "False"}`);
console.log(`DELTA_TS_SIGNED_BUNDLE_SIGNATURE_SHAPE_OK=${result.signatureShapeOk ? "True" : "False"}`);
console.log(`DELTA_TS_SIGNED_BUNDLE_SIGNATURE_OK=${result.signatureOk ? "True" : "False"}`);

if (result.signatureBodyHashOk !== null) {
  console.log(`DELTA_TS_SIGNED_BUNDLE_SIGNATURE_BODY_HASH_OK=${result.signatureBodyHashOk ? "True" : "False"}`);
}

if (result.publicKeyHashOk !== null) {
  console.log(`DELTA_TS_SIGNED_BUNDLE_PUBLIC_KEY_HASH_OK=${result.publicKeyHashOk ? "True" : "False"}`);
}

console.log(`DELTA_TS_SIGNED_BUNDLE_COMPUTED_BUNDLE_HASH=${result.computedBundleHash}`);

if (result.declaredBundleHash) {
  console.log(`DELTA_TS_SIGNED_BUNDLE_DECLARED_BUNDLE_HASH=${result.declaredBundleHash}`);
}

if (result.computedSignatureBodyHash) {
  console.log(`DELTA_TS_SIGNED_BUNDLE_COMPUTED_SIGNATURE_BODY_HASH=${result.computedSignatureBodyHash}`);
}

if (result.declaredSignatureBodyHash) {
  console.log(`DELTA_TS_SIGNED_BUNDLE_DECLARED_SIGNATURE_BODY_HASH=${result.declaredSignatureBodyHash}`);
}

if (result.publicKeyHash) {
  console.log(`DELTA_TS_SIGNED_BUNDLE_PUBLIC_KEY_HASH=${result.publicKeyHash}`);
}

for (const warning of result.warnings) {
  console.log(`DELTA_TS_SIGNED_BUNDLE_WARNING=${warning}`);
}

for (const error of result.errors) {
  console.log(`DELTA_TS_SIGNED_BUNDLE_REASON=${error}`);
}

process.exit(result.ok ? 0 : 1);
