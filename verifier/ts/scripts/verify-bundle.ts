import { verifyDeltaBundle } from "../src/bundleVerifier.js";

function argValue(flag: string): string | null {
  const index = process.argv.indexOf(flag);
  if (index === -1) return null;
  return process.argv[index + 1] ?? null;
}

const bundle = argValue("--bundle") ?? process.argv[2];

if (!bundle) {
  console.error("usage: npm run verify-bundle -- --bundle path/to/file.delta");
  process.exit(2);
}

const result = verifyDeltaBundle(bundle);

console.log(`DELTA_TS_BUNDLE_VERIFY_OK=${result.ok ? "True" : "False"}`);
console.log(`DELTA_TS_BUNDLE_PROFILE=${result.profile}`);
console.log(`DELTA_TS_BUNDLE_FILE=${result.bundlePath}`);
console.log(`DELTA_TS_BUNDLE_MANIFEST_OK=${result.manifestOk ? "True" : "False"}`);
console.log(`DELTA_TS_BUNDLE_ARTIFACT_COUNT=${result.artifactCount}`);

for (const warning of result.warnings) console.log(`DELTA_TS_BUNDLE_WARNING=${warning}`);
for (const error of result.errors) console.log(`DELTA_TS_BUNDLE_REASON=${error}`);

process.exit(result.ok ? 0 : 1);
