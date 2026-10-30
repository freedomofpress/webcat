// One rule table per document, a row per field or invariant, in check order.
// A row with `schema` applies to those versions only, where 0 is a document
// without the schema field. Fields no applicable row names are ignored. A
// valid document older than the configured minimum version is deprecated.
import {
  Manifest,
  SigstoreEnrollment,
  SigsumEnrollment,
} from "./interfaces/bundle";
import {
  WebcatError,
  WebcatErrorCode,
  WebcatErrorCodeAny,
} from "./interfaces/errors";

export type Rule<T> = {
  // Absent for a rule over the whole document.
  field?: keyof T & string;
  // Absent means every version.
  schema?: number[];
  // Gets the field value, undefined when absent, or the document.
  test: (value: unknown, doc: T) => boolean;
  error: WebcatErrorCodeAny;
  // Rendered into the error details.
  detail?: (value: unknown, doc: T) => string[];
};

export type Schema<T> = {
  // The field that carries the schema version.
  field: keyof T & string;
  // For a version below the configured minimum.
  deprecated: WebcatErrorCodeAny;
  rules: Rule<T>[];
};

export const SUPPORTED_SCHEMA = 1;

export function validate<T extends object>(
  doc: T,
  schema: Schema<T>,
  minSchema = 0,
): WebcatError | null {
  const record = doc as Record<string, unknown>;
  const version = record[schema.field] ?? 0;
  for (const rule of schema.rules) {
    const value = rule.field === undefined ? doc : record[rule.field];
    const applies =
      rule.schema === undefined ||
      (typeof version === "number" && rule.schema.includes(version));
    if (!applies) continue;
    if (!rule.test(value, doc)) {
      return new WebcatError(rule.error, rule.detail?.(value, doc));
    }
  }
  if ((version as number) < minSchema) {
    return new WebcatError(schema.deprecated, [
      String(version),
      String(minSchema),
    ]);
  }
  return null;
}

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);
const isFiniteNumber = (v: unknown): v is number =>
  typeof v === "number" && Number.isFinite(v);
const isOptionalString = (v: unknown) =>
  v === undefined || typeof v === "string";
const isSchemaVersion = (v: unknown) =>
  v === undefined || (Number.isInteger(v) && (v as number) >= 1);
const isSupportedSchema = (v: unknown) =>
  v === undefined || (v as number) <= SUPPORTED_SCHEMA;

// Unpadded base64url SHA-256; the last character's padding bits must be zero.
const SHA256_BASE64URL = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;
const isHash = (v: unknown) =>
  typeof v === "string" && SHA256_BASE64URL.test(v);

const { Enrollment, Manifest: ManifestError } = WebcatErrorCode;

export const sigsumEnrollmentSchema: Schema<SigsumEnrollment> = {
  field: "enrollment_schema",
  deprecated: Enrollment.SCHEMA_DEPRECATED,
  rules: [
    {
      field: "enrollment_schema",
      test: isSchemaVersion,
      error: Enrollment.SCHEMA_INVALID,
    },
    {
      field: "enrollment_schema",
      test: isSupportedSchema,
      error: Enrollment.SCHEMA_UNSUPPORTED,
    },
    {
      field: "policy",
      test: (v) => typeof v === "string",
      error: Enrollment.POLICY_MALFORMED,
    },
    {
      field: "policy",
      test: (v) => (v as string).length > 0 && (v as string).length <= 8192,
      error: Enrollment.POLICY_LENGTH,
    },
    {
      field: "signers",
      test: Array.isArray,
      error: Enrollment.SIGNERS_MALFORMED,
    },
    {
      field: "signers",
      test: (v) => (v as unknown[]).length > 0,
      error: Enrollment.SIGNERS_EMPTY,
    },
    {
      field: "signers",
      test: (v) => (v as unknown[]).every((key) => typeof key === "string"),
      error: Enrollment.SIGNERS_KEY_MALFORMED,
      detail: (v) => [
        String((v as unknown[]).find((key) => typeof key !== "string")),
      ],
    },
    {
      field: "threshold",
      test: (v) => Number.isInteger(v) && (v as number) >= 1,
      error: Enrollment.THRESHOLD_MALFORMED,
    },
    {
      test: (_, e) => e.threshold <= e.signers.length,
      error: Enrollment.THRESHOLD_IMPOSSIBLE,
    },
    {
      field: "max_age",
      test: isFiniteNumber,
      error: Enrollment.MAX_AGE_MALFORMED,
    },
    {
      field: "logs",
      test: (v) =>
        isObject(v) &&
        Object.keys(v).length > 0 &&
        Object.values(v).every((url) => typeof url === "string"),
      error: Enrollment.LOGS_MALFORMED,
    },
  ],
};

export const sigstoreEnrollmentSchema: Schema<SigstoreEnrollment> = {
  field: "enrollment_schema",
  deprecated: Enrollment.SCHEMA_DEPRECATED,
  rules: [
    {
      field: "enrollment_schema",
      test: isSchemaVersion,
      error: Enrollment.SCHEMA_INVALID,
    },
    {
      field: "enrollment_schema",
      test: isSupportedSchema,
      error: Enrollment.SCHEMA_UNSUPPORTED,
    },
    {
      field: "trusted_root",
      test: (v) => Boolean(v),
      error: Enrollment.TRUSTED_ROOT_MISSING,
    },
    { field: "claims", test: isObject, error: Enrollment.CLAIMS_MISSING },
    {
      field: "claims",
      test: (v) => Object.keys(v as object).length > 0,
      error: Enrollment.CLAIMS_EMPTY,
    },
    {
      field: "claims",
      test: (v) =>
        Object.entries(v as object).every(
          ([oid, value]) =>
            oid.length > 0 && typeof value === "string" && value.length > 0,
        ),
      error: Enrollment.CLAIMS_MALFORMED,
      detail: (v) =>
        Object.entries(v as object)
          .filter(
            ([oid, value]) =>
              oid.length > 0 &&
              !(typeof value === "string" && value.length > 0),
          )
          .map(([oid]) => String(oid))
          .slice(0, 1),
    },
    {
      field: "max_age",
      test: isFiniteNumber,
      error: Enrollment.MAX_AGE_MALFORMED,
    },
  ],
};

export const manifestSchema: Schema<Manifest> = {
  field: "manifest_schema",
  deprecated: ManifestError.SCHEMA_DEPRECATED,
  rules: [
    {
      field: "manifest_schema",
      test: isSchemaVersion,
      error: ManifestError.SCHEMA_INVALID,
    },
    {
      field: "manifest_schema",
      test: isSupportedSchema,
      error: ManifestError.SCHEMA_UNSUPPORTED,
    },
    {
      field: "files",
      test: (v) => isObject(v) && Object.keys(v).length > 0,
      error: ManifestError.FILES_MISSING,
    },
    {
      field: "files",
      test: (v) => Object.values(v as object).every(isHash),
      error: ManifestError.FILES_MALFORMED,
      detail: (v) => [
        Object.entries(v as object).find(([, hash]) => !isHash(hash))?.[0] ??
          "",
      ],
    },
    {
      field: "default_csp",
      test: (v) => Boolean(v),
      error: ManifestError.DEFAULT_CSP_MISSING,
    },
    // Auditors fetch each fallback at /.well-known/webcat/hashes/<hash>.
    {
      field: "fallback_hashes",
      schema: [1],
      test: (v) => v === undefined || (Array.isArray(v) && v.every(isHash)),
      error: ManifestError.FALLBACK_HASHES_MALFORMED,
    },
    {
      field: "wasm",
      test: (v) => Boolean(v),
      error: ManifestError.WASM_MISSING,
    },
    {
      field: "source",
      schema: [1],
      test: isOptionalString,
      error: ManifestError.PROVENANCE_MALFORMED,
      detail: () => ["source"],
    },
    {
      field: "artifact",
      schema: [1],
      test: isOptionalString,
      error: ManifestError.PROVENANCE_MALFORMED,
      detail: () => ["artifact"],
    },
    {
      field: "default_index",
      schema: [0],
      test: isOptionalString,
      error: ManifestError.FALLBACK_HASHES_MALFORMED,
    },
    // Must name a file; originstate.ts turns it into fallback_hashes.
    {
      field: "default_fallback",
      schema: [0],
      test: (v, m) =>
        v === undefined || (typeof v === "string" && isHash(m.files?.[v])),
      error: ManifestError.FALLBACK_HASHES_MALFORMED,
    },
  ],
};
