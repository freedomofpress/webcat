// Unused imports to resolve links in documentation comments
// @dpdm-ignore
import { validateCSP } from "../validators"; // eslint-disable-line @typescript-eslint/no-unused-vars
import { EnrollmentTypes } from "./bundle"; // eslint-disable-line @typescript-eslint/no-unused-vars

/**
 * Error codes related to bundle fetching.
 */
export enum WebcatErrorFetch {
  /** Unused. */
  FETCH_PROMISE_MISSING = "ERR_WEBCAT_BUNDLE_FETCH_PROMISE_MISSING",
  /**
   * The {@link fetch} API call failed. Potential causes include network errors
   * or misconfigured bundle paths.
   */
  FETCH_ERROR = "ERR_WEBCAT_BUNDLE_FETCH_ERROR",
}

/**
 * Error codes related to bundle validation.
 */
export enum WebcatErrorBundle {
  /** The bundle is invalid JSON. */
  MALFORMED = "ERR_WEBCAT_BUNDLE_MALFORMED",
  /** The bundle is missing the enrollment object. */
  ENROLLMENT_MISSING = "ERR_WEBCAT_BUNDLE_MISSING_ENROLLMENT",
  /** The bundle is missing the manifest object. */
  MANIFEST_MISSING = "ERR_WEBCAT_BUNDLE_MISSING_MANIFEST",
  /** The bundle is missing its signatures. */
  SIGNATURES_MISSING = "ERR_WEBCAT_BUNDLE_MISSING_SIGNATURES",
}

/**
 * Error codes related to enrollment validation
 */
export enum WebcatErrorEnrollment {
  // #region Generic
  /**
   * The enrollment is not of one of the
   * {@link EnrollmentTypes | supported enrollment types}.
   */
  TYPE_INVALID = "ERR_WEBCAT_ENROLLMENT_TYPE_INVALID",
  /**
   * The enrollment object does not match its published hash.
   */
  MISMATCH = "ERR_WEBCAT_ENROLLMENT_MISMATCH",
  // #endregion

  // #region Sigsum-specific
  /**
   * The policy on the enrollment does not match the expected format.
   * Sigsum-specific.
   */
  POLICY_MALFORMED = "ERR_WEBCAT_ENROLLMENT_POLICY_MALFORMED",
  /**
   * The policy on the enrollment is either empty or too long. Sigsum-specific.
   */
  POLICY_LENGTH = "ERR_WEBCAT_ENROLLMENT_POLICY_LENGTH",

  /**
   * The value of the signers property is not an array. Sigsum-specific.
   */
  SIGNERS_MALFORMED = "ERR_WEBCAT_ENROLLMENT_SIGNERS_MALFORMED",
  /**
   * The signers array is empty. Sigsum-specific.
   */
  SIGNERS_EMPTY = "ERR_WEBCAT_ENROLLMENT_SIGNERS_EMPTY",
  /**
   * The signer keys are not in the expected format. Sigsum-specific.
   */
  SIGNERS_KEY_MALFORMED = "ERR_WEBCAT_ENROLLMENT_SIGNERS_KEY_MALFORMED",

  /**
   * The signature threshold is not in the expected format. Sigsum-specific.
   */
  THRESHOLD_MALFORMED = "ERR_WEBCAT_ENROLLMENT_THRESHOLD_MALFORMED",
  /**
   * The signers threshold is higher than the number of signers and, hence,
   * unreachable. Sigsum-specific.
   */
  THRESHOLD_IMPOSSIBLE = "ERR_WEBCAT_ENROLLMENT_THRESHOLD_IMPOSSIBLE",

  /**
   * The logs are not in the expected format. Sigsum-specific.
   */
  LOGS_MALFORMED = "ERR_WEBCAT_ENROLLMENT_LOGS_MALFORMED",
  // #endregion

  // #region Shared
  /** The enrollment max age is not in the expected format. */
  MAX_AGE_MALFORMED = "ERR_WEBCAT_ENROLLMENT_MAX_AGE_MALFORMED",
  // #endregion

  // #region Sigstore-specific
  /**
   * The enrollment is missing the trusted_root property. Sigstore-specific.
   */
  TRUSTED_ROOT_MISSING = "ERR_WEBCAT_ENROLLMENT_TRUSTED_ROOT_MISSING",

  /**
   * The enrollment is missing the claims property. Sigstore-specific.
   */
  CLAIMS_MISSING = "ERR_WEBCAT_ENROLLMENT_CLAIMS_MISSING",
  /**
   * The enrollment claims are not in the expected format. Sigstore-specific.
   */
  CLAIMS_MALFORMED = "ERR_WEBCAT_ENROLLMENT_CLAIMS_MALFORMED",
  /**
   * The enrollment claims array is empty. Sigstore-specific.
   */
  CLAIMS_EMPTY = "ERR_WEBCAT_ENROLLMENT_CLAIMS_EMPTY",
  // #endregion
}

/**
 * Error codes related to manifest validation.
 */
export enum WebcatErrorManifest {
  /**
   * The manifest could not be verified against the signatures.
   */
  VERIFY_FAILED = "ERR_WEBCAT_MANIFEST_VERIFY_FAILED",
  /**
   * The number of valid signatures did not satisfy the threshold specified on
   * the enrollment. Sigsum-specific.
   */
  THRESHOLD_UNSATISFIED = "ERR_WEBCAT_MANIFEST_THRESHOLD_UNSATISFIED",
  /**
   * The timestamp property is missing from the manifest. Sigsum-specific.
   */
  TIMESTAMP_MISSING = "ERR_WEBCAT_MANIFEST_MISSING_TIMESTAMP",
  /**
   * The timestamp value could not be verified. Sigsum-specific.
   */
  TIMESTAMP_VERIFY_FAILED = "ERR_WEBCAT_MANIFEST_TIMESTAMP_VERIFY_FAILED",
  /**
   * The manifest has expired.
   */
  EXPIRED = "ERR_WEBCAT_MANIFEST_EXPIRED",
  /**
   * No file list is present on the manifest, or the file list is empty.
   */
  FILES_MISSING = "ERR_WEBCAT_MANIFEST_FILES_MISSING",
  /**
   * No default index is present on the manifest.
   */
  DEFAULT_INDEX_MISSING = "ERR_WEBCAT_MANIFEST_DEFAULT_INDEX_MISSING",
  /**
   * The default index does not match any file in the file list.
   */
  DEFAULT_INDEX_MISSING_FILE = "ERR_WEBCAT_MANIFEST_DEFAULT_INDEX_MISSING_FILE",
  /**
   * No default fallback is present on the manifest.
   */
  DEFAULT_FALLBACK_MISSING = "ERR_WEBCAT_MANIFEST_DEFAULT_FALLBACK_MISSING",
  /**
   * The default fallback does not match any file in the file list.
   */
  DEFAULT_FALLBACK_MISSING_FILE = "ERR_WEBCAT_MANIFEST_DEFAULT_FALLBACK_MISSING_FILE",
  /**
   * No default CSP is present on the manifest.
   */
  DEFAULT_CSP_MISSING = "ERR_WEBCAT_MANIFEST_DEFAULT_CSP_MISSING",
  /**
   * The default CSP is invalid. See {@link validateCSP}.
   */
  DEFAULT_CSP_INVALID = "ERR_WEBCAT_MANIFEST_DEFAULT_CSP_INVALID",
  /**
   * An extra CSP is invalid. See {@link validateCSP}.
   */
  EXTRA_CSP_INVALID = "ERR_WEBCAT_MANIFEST_EXTRA_CSP_INVALID",
  /**
   * The extra CSP object is not in the expected format.
   */
  EXTRA_CSP_MALFORMED = "ERR_WEBCAT_MANIFEST_EXTRA_CSP_MALFORMED",
  /**
   * No wasm property is present on the manifest.
   */
  WASM_MISSING = "ERR_WEBCAT_MANIFEST_WASM_MISSING",
}

/**
 * Error codes related to CSP validation.
 */
export enum WebcatErrorCSP {
  /** Unused. */
  PARSE_FAILED = "ERR_WEBCAT_CSP_PARSE_FAILED",
  /**
   * The CSP returned by the server did not match any of the CSPs declared on
   * the manifest.
   */
  MISMATCH = "ERR_WEBCAT_CSP_MISMATCH",
}

/**
 * Error codes related to header validation.
 */
export enum WebcatErrorHeaders {
  /**
   * Response headers are unavailable for inspection.
   */
  MISSING = "ERR_WEBCAT_HEADERS_MISSING",
  /**
   * A redirection to an external origin was attempted via a location header.
   */
  LOCATION_EXTERNAL = "ERR_WEBCAT_HEADERS_LOCATION_EXTERNAL",
  /**
   * A subresource request was redirected via a location header.
   */
  LOCATION_SUBRESOURCE = "ERR_WEBCAT_HEADERS_LOCATION_SUBRESOURCE",
  /**
   * The server returned a forbidden header.
   */
  FORBIDDEN = "ERR_WEBCAT_HEADERS_FORBIDDEN",
  /**
   * The server returned a duplicate critical header.
   */
  DUPLICATE = "ERR_WEBCAT_HEADERS_DUPLICATE",
  /**
   * A critical header was missing from the response.
   */
  MISSING_CRITICAL = "ERR_WEBCAT_HEADERS_MISSING_CRITICAL",
  /**
   * An enrollment header did not match the expected format.
   */
  ENROLLMENT_MALFORMED = "ERR_WEBCAT_HEADERS_ENROLLMENT_MALFORMED",
}

/**
 * Error codes related to request URL validation.
 */
export enum WebcatErrorURL {
  /**
   * A request was issued with an unsupported protocol or port.
   */
  UNSUPPORTED = "ERR_WEBCAT_URL_UNSUPPORTED",
}

/**
 * Error codes related to file content validation.
 */
export enum WebcatErrorFile {
  /**
   * The file is not present on the manifest.
   */
  MISSING = "ERR_WEBCAT_FILE_MISSING",
  /**
   * The file contents do not match the hash on the manifest.
   */
  MISMATCH = "ERR_WEBCAT_FILE_MISMATCH",
}

/**
 * All user-facing error codes.
 */
export const WebcatErrorCode = {
  /** {@inheritDoc WebcatErrorFetch} */
  Fetch: { ...WebcatErrorFetch },
  /** {@inheritDoc WebcatErrorBundle} */
  Bundle: { ...WebcatErrorBundle },
  /** {@inheritDoc WebcatErrorEnrollment} */
  Enrollment: { ...WebcatErrorEnrollment },
  /** {@inheritDoc WebcatErrorManifest} */
  Manifest: { ...WebcatErrorManifest },
  /** {@inheritDoc WebcatErrorCSP} */
  CSP: { ...WebcatErrorCSP },
  /** {@inheritDoc WebcatErrorHeaders} */
  Headers: { ...WebcatErrorHeaders },
  /** {@inheritDoc WebcatErrorURL} */
  URL: { ...WebcatErrorURL },
  /** {@inheritDoc WebcatErrorFile} */
  File: { ...WebcatErrorFile },
} as const;

/**
 * Error code type.
 */
export type WebcatErrorCodeAny =
  | WebcatErrorFetch
  | WebcatErrorBundle
  | WebcatErrorEnrollment
  | WebcatErrorManifest
  | WebcatErrorCSP
  | WebcatErrorHeaders
  | WebcatErrorURL
  | WebcatErrorFile;

/**
 * Error class for user-facing errors.
 */
export class WebcatError extends Error {
  constructor(
    public readonly code: WebcatErrorCodeAny,
    public readonly details?: string[],
  ) {
    super(code);
    this.name = "WebcatError";
  }
}
