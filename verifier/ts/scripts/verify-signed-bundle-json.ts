import {
  argValue,
  internalErrorResult,
  printJson,
  usageResult,
  verificationResult
} from "../src/cliResult.js";
import { verifySignedBundle } from "../src/signedBundleVerifier.js";

const command = "verify-signed-bundle-json";
const bundle = argValue("--bundle") ?? process.argv[2] ?? null;
const signature = argValue("--signature");
const publicKey = argValue("--public-key");

if (!bundle || !signature) {
  const result = usageResult(
    command,
    "usage: npm run verify-signed-bundle-json -- --bundle path/to/file.delta --signature path/to/file.sig.json [--public-key ed25519:<hex-or-base64url>]"
  );
  printJson(result);
  process.exit(result.code);
}

try {
  const signedBundleResult = await verifySignedBundle(bundle, signature, publicKey ?? undefined);
  const result = verificationResult(
    command,
    signedBundleResult.ok,
    signedBundleResult,
    signedBundleResult.errors,
    signedBundleResult.warnings
  );
  printJson(result);
  process.exit(result.code);
} catch (err) {
  const result = internalErrorResult(command, err);
  printJson(result);
  process.exit(result.code);
}
