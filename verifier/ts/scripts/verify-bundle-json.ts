import {
  argValue,
  internalErrorResult,
  printJson,
  usageResult,
  verificationResult
} from "../src/cliResult.js";
import { verifyDeltaBundle } from "../src/bundleVerifier.js";

const command = "verify-bundle-json";
const bundle = argValue("--bundle") ?? process.argv[2] ?? null;

if (!bundle) {
  const result = usageResult(command, "usage: npm run verify-bundle-json -- --bundle path/to/file.delta");
  printJson(result);
  process.exit(result.code);
}

try {
  const bundleResult = verifyDeltaBundle(bundle);
  const result = verificationResult(
    command,
    bundleResult.ok,
    bundleResult,
    bundleResult.errors,
    bundleResult.warnings
  );
  printJson(result);
  process.exit(result.code);
} catch (err) {
  const result = internalErrorResult(command, err);
  printJson(result);
  process.exit(result.code);
}
