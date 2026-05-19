import { createHash } from "node:crypto";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const AdmZipConstructor = require("adm-zip");

export const BUNDLE_PROFILE = "delta_typescript_bundle_verifier_v2_9_3";
export const MANIFEST_NAME = "bundle_manifest.json";

const FORBIDDEN_FILENAME_FRAGMENTS = [
  "private",
  "secret",
  "password",
  "passwd",
  "token",
  ".pem",
  ".key",
  "id_rsa",
  "id_dsa",
  "decrypted",
  "raw-evidence",
  "raw_evidence"
];

type ZipEntryLike = {
  entryName: string;
  isDirectory: boolean;
  getData: () => Buffer;
};

type ZipLike = {
  getEntries: () => ZipEntryLike[];
};

export interface BundleArtifactRef {
  label: string;
  path: string;
  sha256: string | null;
  sizeBytes: number | null;
}

export interface BundleVerificationResult {
  ok: boolean;
  profile: string;
  bundlePath: string;
  manifestOk: boolean;
  artifactCount: number;
  errors: string[];
  warnings: string[];
}

export class DeltaBundleVerifierError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DeltaBundleVerifierError";
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function sha256Prefixed(data: Buffer): string {
  return `sha256:${createHash("sha256").update(data).digest("hex")}`;
}

function normalizeHash(value: string): string {
  const trimmed = value.trim();
  return trimmed.startsWith("sha256:") ? trimmed : `sha256:${trimmed}`;
}

export function normalizeEntryName(name: string): string {
  const normalized = name.replace(/\\/g, "/");

  if (normalized.length === 0) {
    throw new DeltaBundleVerifierError("empty ZIP entry name");
  }

  if (normalized.startsWith("/") || /^[A-Za-z]:/.test(normalized)) {
    throw new DeltaBundleVerifierError(`absolute path rejected: ${name}`);
  }

  const parts = normalized.split("/");
  if (parts.some((part) => part === ".." || part.length === 0)) {
    throw new DeltaBundleVerifierError(`path traversal or empty path segment rejected: ${name}`);
  }

  return normalized;
}

export function hasForbiddenFilenameFragment(name: string): string | null {
  const lower = name.toLowerCase();

  for (const fragment of FORBIDDEN_FILENAME_FRAGMENTS) {
    if (lower.includes(fragment)) {
      return fragment;
    }
  }

  return null;
}

function stringField(obj: Record<string, unknown>, names: string[]): string | null {
  for (const name of names) {
    const value = obj[name];
    if (typeof value === "string" && value.length > 0) {
      return value;
    }
  }
  return null;
}

function numberField(obj: Record<string, unknown>, names: string[]): number | null {
  for (const name of names) {
    const value = obj[name];
    if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) {
      return value;
    }
  }
  return null;
}

function collectArtifactObject(label: string, obj: Record<string, unknown>): BundleArtifactRef | null {
  const path = stringField(obj, [
    "path",
    "filename",
    "file",
    "name",
    "artifact_path",
    "bundle_path",
    "bundle_filename",
    "artifact",
    "artifact_name"
  ]);

  if (!path) {
    return null;
  }

  const sha256 = stringField(obj, [
    "sha256",
    "sha256_hash",
    "hash",
    "digest",
    "artifact_sha256",
    "content_sha256",
    "artifact_hash",
    "file_hash"
  ]);

  const sizeBytes = numberField(obj, [
    "size_bytes",
    "size",
    "length",
    "artifact_size_bytes",
    "file_size_bytes"
  ]);

  const role = stringField(obj, ["role", "type", "id", "label"]) ?? label;

  return {
    label: role,
    path,
    sha256: sha256 ? normalizeHash(sha256) : null,
    sizeBytes
  };
}

function extractArtifactRefsStructured(manifest: Record<string, unknown>): BundleArtifactRef[] {
  const refs: BundleArtifactRef[] = [];

  const addFromValue = (label: string, value: unknown): void => {
    if (typeof value === "string" && value.length > 0) {
      refs.push({ label, path: value, sha256: null, sizeBytes: null });
      return;
    }

    if (isObject(value)) {
      const direct = collectArtifactObject(label, value);
      if (direct) {
        refs.push(direct);
        return;
      }

      for (const [nestedLabel, nestedValue] of Object.entries(value)) {
        addFromValue(nestedLabel, nestedValue);
      }
    }
  };

  for (const key of ["artifacts", "contained_artifacts", "bundle_artifacts", "files"]) {
    const value = manifest[key];

    if (Array.isArray(value)) {
      value.forEach((item, index) => addFromValue(`artifact_${index}`, item));
    } else if (isObject(value)) {
      for (const [label, item] of Object.entries(value)) {
        addFromValue(label, item);
      }
    }
  }

  const deduped = new Map<string, BundleArtifactRef>();
  for (const ref of refs) {
    deduped.set(ref.path, ref);
  }
  return [...deduped.values()];
}

function extractArtifactRefsByManifestText(
  manifest: Record<string, unknown>,
  entriesByName: Map<string, ZipEntryLike>
): BundleArtifactRef[] {
  const manifestText = JSON.stringify(manifest);
  const refs: BundleArtifactRef[] = [];

  for (const [entryName, entry] of entriesByName.entries()) {
    if (entryName === MANIFEST_NAME) {
      continue;
    }

    if (!manifestText.includes(entryName)) {
      continue;
    }

    const actualHash = sha256Prefixed(entry.getData());
    const actualHex = actualHash.slice("sha256:".length);
    const actualSize = entry.getData().length;

    refs.push({
      label: entryName.replace(/[^A-Za-z0-9]+/g, "_").replace(/^_+|_+$/g, "") || "artifact",
      path: entryName,
      sha256: manifestText.includes(actualHash) || manifestText.includes(actualHex) ? actualHash : null,
      sizeBytes: manifestText.includes(String(actualSize)) ? actualSize : null
    });
  }

  return refs;
}

export function extractArtifactRefs(
  manifest: Record<string, unknown>,
  entriesByName?: Map<string, ZipEntryLike>
): BundleArtifactRef[] {
  const structured = extractArtifactRefsStructured(manifest);

  if (structured.length > 0 || !entriesByName) {
    return structured;
  }

  return extractArtifactRefsByManifestText(manifest, entriesByName);
}

function readManifest(entriesByName: Map<string, ZipEntryLike>, errors: string[]): Record<string, unknown> | null {
  const manifestEntry = entriesByName.get(MANIFEST_NAME);

  if (!manifestEntry) {
    errors.push("missing_required_bundle_manifest_json");
    return null;
  }

  try {
    const parsed = JSON.parse(manifestEntry.getData().toString("utf-8")) as unknown;
    if (!isObject(parsed)) {
      errors.push("bundle_manifest_json_not_object");
      return null;
    }
    return parsed;
  } catch (err) {
    errors.push(`bundle_manifest_json_parse_error:${err instanceof Error ? err.message : "unknown"}`);
    return null;
  }
}

export function verifyDeltaBundle(bundlePath: string): BundleVerificationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  let zip: ZipLike;
  try {
    zip = new AdmZipConstructor(bundlePath) as ZipLike;
  } catch (err) {
    return {
      ok: false,
      profile: BUNDLE_PROFILE,
      bundlePath,
      manifestOk: false,
      artifactCount: 0,
      errors: [`zip_open_error:${err instanceof Error ? err.message : "unknown"}`],
      warnings
    };
  }

  const entries = zip.getEntries().filter((entry) => !entry.isDirectory);
  const entriesByName = new Map<string, ZipEntryLike>();

  for (const entry of entries) {
    try {
      const normalized = normalizeEntryName(entry.entryName);

      if (entriesByName.has(normalized)) {
        errors.push(`duplicate_filename_rejected:${normalized}`);
        continue;
      }

      const forbidden = hasForbiddenFilenameFragment(normalized);
      if (forbidden) {
        errors.push(`forbidden_sensitive_filename_fragment:${normalized}:${forbidden}`);
      }

      entriesByName.set(normalized, entry);
    } catch (err) {
      errors.push(err instanceof Error ? err.message : "unsafe_zip_entry");
    }
  }

  const manifest = readManifest(entriesByName, errors);
  const refs = manifest ? extractArtifactRefs(manifest, entriesByName) : [];

  if (manifest && refs.length === 0) {
    errors.push("no_artifacts_declared_in_manifest");
  }

  const referenced = new Set<string>();

  for (const ref of refs) {
    let normalizedPath: string;

    try {
      normalizedPath = normalizeEntryName(ref.path);
    } catch (err) {
      errors.push(`artifact_path_invalid:${ref.label}:${err instanceof Error ? err.message : "invalid_path"}`);
      continue;
    }

    if (normalizedPath === MANIFEST_NAME) {
      errors.push(`artifact_must_not_reference_manifest:${ref.label}`);
      continue;
    }

    referenced.add(normalizedPath);

    const entry = entriesByName.get(normalizedPath);
    if (!entry) {
      errors.push(`artifact_missing:${ref.label}:${normalizedPath}`);
      continue;
    }

    if (!ref.sha256) {
      errors.push(`artifact_sha256_missing:${ref.label}:${normalizedPath}`);
    } else {
      const actualHash = sha256Prefixed(entry.getData());
      if (actualHash !== ref.sha256) {
        errors.push(`artifact_sha256_mismatch:${ref.label}:${normalizedPath}`);
      }
    }

    if (ref.sizeBytes === null) {
      warnings.push(`artifact_size_bytes_not_declared:${ref.label}:${normalizedPath}`);
    } else {
      const actualSize = entry.getData().length;
      if (actualSize !== ref.sizeBytes) {
        errors.push(`artifact_size_bytes_mismatch:${ref.label}:${normalizedPath}:declared=${ref.sizeBytes}:actual=${actualSize}`);
      }
    }
  }

  for (const name of entriesByName.keys()) {
    if (name === MANIFEST_NAME) {
      continue;
    }
    if (!referenced.has(name)) {
      errors.push(`unreferenced_bundle_artifact:${name}`);
    }
  }

  return {
    ok: errors.length === 0,
    profile: BUNDLE_PROFILE,
    bundlePath,
    manifestOk: manifest !== null,
    artifactCount: refs.length,
    errors,
    warnings
  };
}
