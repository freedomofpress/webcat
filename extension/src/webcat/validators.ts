import {
  AllOf,
  EXTENSION_OID_OTHERNAME,
  PolicyError,
  SigstoreVerifier,
  VerificationPolicy,
  X509Certificate,
} from "@freedomofpress/sigstore-browser";
import { verifyMessageWithCompiledPolicy } from "@freedomofpress/sigsum";
import {
  evalQuorumBytecode,
  importAndHashAll,
  parseCompiledPolicy,
} from "@freedomofpress/sigsum/dist/compiledPolicy";
import {
  verifyCosignedTreeHead,
  verifySignedTreeHead,
} from "@freedomofpress/sigsum/dist/crypto";
import { parseCosignedTreeHead } from "@freedomofpress/sigsum/dist/proof";
import {
  Base64KeyHash,
  CosignedTreeHead,
  KeyHash,
  RawPublicKey,
} from "@freedomofpress/sigsum/dist/types";

import { canonicalize } from "./canonicalize";
import { base64UrlToUint8Array, stringToUint8Array } from "./encoding";
import {
  Manifest,
  SigstoreEnrollment,
  SigstoreSignatures,
  SigsumEnrollment,
  SigsumSignatures,
} from "./interfaces/bundle";
import { WebcatError, WebcatErrorCode } from "./interfaces/errors";
import { parseContentSecurityPolicy } from "./parsers";

/**
 * Validates a Content Security Policy. Enforces the restrictions outlined in
 * {@link https://docs.webcat.tech/webapp-developers/CSP.html | the CSP docs}.
 * Host sources are never allowed, so no enrollment lookup is needed.
 *
 * @param csp The policy string to validate.
 */
export function validateCSP(csp: string) {
  // See https://github.com/freedomofpress/webcat/issues/9
  // https://github.com/freedomofpress/webcat/issues/3

  enum directives {
    DefaultSrc = "default-src",
    ScriptSrc = "script-src",
    ScriptSrcElem = "script-src-elem",
    StyleSrc = "style-src",
    StyleSrcElem = "style-src-elem",
    ObjectSrc = "object-src",
    ChildSrc = "child-src",
    FrameSrc = "frame-src",
    WorkerSrc = "worker-src",
  }

  enum source_keywords {
    None = "'none'",
    Self = "'self'",
    WasmUnsafeEval = "'wasm-unsafe-eval'",
    UnsafeInline = "'unsafe-inline'",
    UnsafeEval = "'unsafe-eval'",
    UnsafeHashes = "'unsafe-hashes'",
    StrictDynamic = "'strict-dynamic'",
  }

  const script_keywords = [
    source_keywords.None,
    source_keywords.Self,
    source_keywords.WasmUnsafeEval,
  ];
  // TODO eventually 'unsafe-inline' and 'unsafe-hashes' should disappear
  const style_keywords = [
    source_keywords.None,
    source_keywords.Self,
    source_keywords.UnsafeInline,
    source_keywords.UnsafeHashes,
  ];

  // See https://github.com/freedomofpress/webcat/issues/101
  if (csp.includes(",")) {
    throw new Error(`CSP contains a comma: ${csp}`);
  }

  // The spec (and thus the parsing function) has to lowercase the directive names
  const parsedCSP = parseContentSecurityPolicy(csp);

  // Step 1: default-src is 'none' and/or 'self'. A lone 'none' makes every
  // other directive optional. See https://github.com/freedomofpress/webcat/issues/99
  const default_src = parsedCSP.get(directives.DefaultSrc) ?? [];
  for (const src of default_src) {
    if (src !== source_keywords.None && src !== source_keywords.Self) {
      throw new Error(
        `Unexpected or non-allowed default-src directive: ${src}`,
      );
    }
  }
  const default_src_is_none =
    default_src.length === 1 && default_src[0] === source_keywords.None;

  // The directive is required unless `optional`. Each source must be an
  // allowed keyword or, with `hashes`, a 'sha...' hash.
  function validateDirective(
    directive: directives,
    allowed_keywords: source_keywords[],
    hashes = false,
    optional = default_src_is_none,
  ) {
    const list = parsedCSP.get(directive);
    if (!list?.length && !optional) {
      throw new Error(
        `${directives.DefaultSrc} is not none, and ${directive} is not defined.`,
      );
    }
    for (const src of list ?? []) {
      const lower = src.toLowerCase();
      if (
        !(allowed_keywords as string[]).includes(lower) &&
        !(hashes && lower.startsWith("'sha"))
      ) {
        throw new Error(
          `${directive} cannot contain ${src} which is unsupported.`,
        );
      }
    }
  }

  // Step 2: object-src must be 'none'
  validateDirective(directives.ObjectSrc, [source_keywords.None]);

  // Step 3: scripts. Hashes allow inline scripts, see
  // https://github.com/freedomofpress/webcat/pull/111
  validateDirective(directives.ScriptSrc, script_keywords, true);
  validateDirective(
    directives.ScriptSrcElem,
    script_keywords,
    true,
    default_src_is_none || parsedCSP.has(directives.ScriptSrc),
  );

  // Step 4: styles
  validateDirective(directives.StyleSrc, style_keywords, true);
  validateDirective(
    directives.StyleSrcElem,
    style_keywords,
    true,
    default_src_is_none || parsedCSP.has(directives.StyleSrc),
  );

  // Step 5: frame-src / child-src are unrestricted. Enrolled documents are
  // origin-keyed (Origin-Agent-Cluster: ?1) => any frame, same-site or not, is
  // isolated from them. Enrolled frames verify under their own manifest.

  validateDirective(directives.WorkerSrc, [
    source_keywords.None,
    source_keywords.Self,
  ]);
}

export async function witnessTimestampsFromCosignedTreeHead(
  compiledPolicy: Uint8Array,
  treeHead: string,
): Promise<number[]> {
  const compiled = parseCompiledPolicy(compiledPolicy);
  const logs = await importAndHashAll(compiled.logsRaw);
  const witnesses = await importAndHashAll(compiled.witnessesRaw);
  const cosignedTreeHead: CosignedTreeHead = await parseCosignedTreeHead(
    treeHead.split("\n"),
  );

  let logKeyHash: KeyHash | null = null;
  for (const log of logs) {
    if (
      await verifySignedTreeHead(
        cosignedTreeHead.SignedTreeHead,
        log.pub,
        log.hash,
      )
    ) {
      logKeyHash = log.hash;
      break;
    }
  }

  if (!logKeyHash) {
    throw new Error("no log key in policy verified the tree head");
  }

  const present = new Uint8Array(witnesses.length);
  const timestamps: number[] = [];

  for (const [i, witness] of witnesses.entries()) {
    const cosignature = Base64KeyHash.lookup(
      cosignedTreeHead.Cosignatures,
      witness.b64,
    );
    if (!cosignature) continue;

    if (
      await verifyCosignedTreeHead(
        cosignedTreeHead.SignedTreeHead.TreeHead,
        witness.pub,
        logKeyHash,
        cosignature,
      )
    ) {
      present[i] = 1;
      timestamps.push(cosignature.Timestamp);
    }
  }

  if (!evalQuorumBytecode(compiled.quorum, witnesses.length, present)) {
    throw new Error("cosignature quorum not satisfied");
  }

  return timestamps;
}

export function validateSigsumEnrollment(
  enrollment: SigsumEnrollment,
): WebcatError | null {
  if (typeof enrollment.policy !== "string") {
    return new WebcatError(WebcatErrorCode.Enrollment.POLICY_MALFORMED);
  }

  if (enrollment.policy.length === 0 || enrollment.policy.length > 8192) {
    return new WebcatError(WebcatErrorCode.Enrollment.POLICY_LENGTH);
  }

  if (!Array.isArray(enrollment.signers)) {
    return new WebcatError(WebcatErrorCode.Enrollment.SIGNERS_MALFORMED);
  }

  if (enrollment.signers.length === 0) {
    return new WebcatError(WebcatErrorCode.Enrollment.SIGNERS_EMPTY);
  }

  for (const key of enrollment.signers) {
    if (typeof key !== "string") {
      return new WebcatError(WebcatErrorCode.Enrollment.SIGNERS_KEY_MALFORMED, [
        String(key),
      ]);
    }
  }

  if (
    typeof enrollment.threshold !== "number" ||
    !Number.isInteger(enrollment.threshold) ||
    enrollment.threshold < 1
  ) {
    return new WebcatError(WebcatErrorCode.Enrollment.THRESHOLD_MALFORMED);
  }

  if (enrollment.threshold > enrollment.signers.length) {
    return new WebcatError(WebcatErrorCode.Enrollment.THRESHOLD_IMPOSSIBLE);
  }

  if (
    typeof enrollment.max_age !== "number" ||
    !Number.isFinite(enrollment.max_age)
  ) {
    return new WebcatError(WebcatErrorCode.Enrollment.MAX_AGE_MALFORMED);
  }

  if (
    typeof enrollment.logs !== "object" ||
    enrollment.logs === null ||
    Object.keys(enrollment.logs).length === 0
  ) {
    return new WebcatError(WebcatErrorCode.Enrollment.LOGS_MALFORMED);
  }

  for (const [pubkey, url] of Object.entries(enrollment.logs)) {
    if (typeof pubkey !== "string" || typeof url !== "string") {
      return new WebcatError(WebcatErrorCode.Enrollment.LOGS_MALFORMED);
    }
  }

  return null;
}

export function validateSigstoreEnrollment(
  enrollment: SigstoreEnrollment,
): WebcatError | null {
  // Trusted root is mandatory
  if (!enrollment.trusted_root) {
    return new WebcatError(WebcatErrorCode.Enrollment.TRUSTED_ROOT_MISSING);
  }

  if (
    typeof enrollment.claims !== "object" ||
    enrollment.claims === null ||
    Array.isArray(enrollment.claims)
  ) {
    return new WebcatError(WebcatErrorCode.Enrollment.CLAIMS_MISSING);
  }

  if (Object.keys(enrollment.claims).length < 1) {
    return new WebcatError(WebcatErrorCode.Enrollment.CLAIMS_EMPTY);
  }

  for (const [oid, value] of Object.entries(enrollment.claims)) {
    if (typeof oid !== "string" || oid.length < 1) {
      return new WebcatError(WebcatErrorCode.Enrollment.CLAIMS_MALFORMED);
    }
    if (typeof value !== "string" || value.length < 1) {
      return new WebcatError(WebcatErrorCode.Enrollment.CLAIMS_MALFORMED, [
        String(oid),
      ]);
    }
  }

  if (
    typeof enrollment.max_age !== "number" ||
    !Number.isFinite(enrollment.max_age)
  ) {
    return new WebcatError(WebcatErrorCode.Enrollment.MAX_AGE_MALFORMED);
  }

  return null;
}

// File hashes are SHA-256 digests in unpadded base64url, as response.ts
// decodes them. The last character carries two padding bits, which must be
// zero for the encoding to be canonical.
const SHA256_BASE64URL = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;

export function validateManifest(manifest: Manifest): WebcatError | null {
  if (!manifest.files || Object.keys(manifest.files).length < 1) {
    return new WebcatError(WebcatErrorCode.Manifest.FILES_MISSING);
  }

  for (const [path, hash] of Object.entries(manifest.files)) {
    if (!SHA256_BASE64URL.test(hash)) {
      return new WebcatError(WebcatErrorCode.Manifest.FILES_MALFORMED, [path]);
    }
  }

  if (!manifest.default_csp) {
    return new WebcatError(WebcatErrorCode.Manifest.DEFAULT_CSP_MISSING);
  }

  if (!manifest.default_index) {
    return new WebcatError(WebcatErrorCode.Manifest.DEFAULT_INDEX_MISSING);
  }

  if (!manifest.default_fallback) {
    return new WebcatError(WebcatErrorCode.Manifest.DEFAULT_FALLBACK_MISSING);
  }

  if (!manifest.files["/" + manifest.default_index]) {
    return new WebcatError(WebcatErrorCode.Manifest.DEFAULT_INDEX_MISSING_FILE);
  }

  if (!manifest.files[manifest.default_fallback]) {
    return new WebcatError(
      WebcatErrorCode.Manifest.DEFAULT_FALLBACK_MISSING_FILE,
    );
  }

  if (!manifest.wasm) {
    return new WebcatError(WebcatErrorCode.Manifest.WASM_MISSING);
  }

  return null;
}

export async function verifySigsumManifest(
  enrollment: SigsumEnrollment,
  manifest: Manifest,
  signatures: SigsumSignatures,
): Promise<WebcatError | number> {
  // signatures must be a non-null object keyed by public key.
  const untrusted: unknown = signatures;
  if (
    typeof untrusted !== "object" ||
    untrusted === null ||
    Array.isArray(untrusted)
  ) {
    return new WebcatError(WebcatErrorCode.Bundle.SIGNATURES_MISSING);
  }
  // canonicalize returns null for a manifest it cannot encode.
  const canonical = canonicalize(manifest);
  if (canonical === null) {
    return new WebcatError(WebcatErrorCode.Manifest.VERIFY_FAILED);
  }
  const canonicalized = stringToUint8Array(canonical);

  // The purpose of cloning the original list of signers is to have logic to ensure
  // that each signers can at most sign once. Since we are dealing with a lot of
  // transformations (hex, b64, etc) and any of these can have malleability, we want to
  // avoid a scenario where the same signature but with a different public key
  // encoding is counted twice. By removing a signer from the set of possible signers
  // we shold prevent this systematically.
  const remainingSigners = new Set(enrollment.signers);
  let validCount = 0;

  for (const pubKey of Object.keys(signatures)) {
    if (!remainingSigners.has(pubKey)) {
      continue;
    }

    try {
      await verifyMessageWithCompiledPolicy(
        canonicalized,
        new RawPublicKey(base64UrlToUint8Array(pubKey)),
        base64UrlToUint8Array(enrollment.policy),
        signatures[pubKey],
      );
    } catch (e) {
      return new WebcatError(WebcatErrorCode.Manifest.VERIFY_FAILED, [
        String(e),
      ]);
    }

    remainingSigners.delete(pubKey);
    validCount++;
  }

  // Threshold enforcement
  if (validCount < enrollment.threshold) {
    return new WebcatError(WebcatErrorCode.Manifest.THRESHOLD_UNSATISFIED, [
      String(validCount),
      String(enrollment.threshold),
    ]);
  }

  // Timestamp presence
  if (!manifest.timestamp) {
    return new WebcatError(WebcatErrorCode.Manifest.TIMESTAMP_MISSING);
  }

  let timestamps: number[];
  try {
    timestamps = await witnessTimestampsFromCosignedTreeHead(
      base64UrlToUint8Array(enrollment.policy),
      manifest.timestamp,
    );
  } catch (e) {
    return new WebcatError(WebcatErrorCode.Manifest.TIMESTAMP_VERIFY_FAILED, [
      String(e),
    ]);
  }

  // Median timestamp
  const timestamp = timestamps.sort((a, b) => a - b)[
    Math.floor(timestamps.length / 2)
  ];

  const now = Math.floor(Date.now() / 1000);

  // Freshness check
  if (now - timestamp > enrollment.max_age) {
    return new WebcatError(WebcatErrorCode.Manifest.EXPIRED, [
      String(enrollment.max_age),
      String(timestamp),
    ]);
  }

  return timestamp + enrollment.max_age;
}

class ClaimPolicy implements VerificationPolicy {
  constructor(
    private oid: string,
    private expected: string,
  ) {}

  private claimMatches(got: string): boolean {
    if (this.expected.startsWith("^")) {
      const expectedPrefix = this.expected.slice(1);
      return got.startsWith(expectedPrefix);
    }

    return got === this.expected;
  }

  verify(cert: X509Certificate): void {
    // Special case: SubjectAltName (2.5.29.17) ---
    if (this.oid === "2.5.29.17") {
      const sanExt = cert.extSubjectAltName;
      if (!sanExt) {
        throw new PolicyError("Certificate missing SubjectAlternativeName");
      }

      const allSans = new Set<string>();

      if (sanExt.rfc822Name) allSans.add(sanExt.rfc822Name);
      if (sanExt.uri) allSans.add(sanExt.uri);

      // Fulcio identity lives in SAN otherName
      const other = sanExt.otherName(EXTENSION_OID_OTHERNAME);
      if (other) allSans.add(other);

      const sanMatches = [...allSans].some((san) => this.claimMatches(san));

      if (!sanMatches) {
        throw new PolicyError(
          `SAN mismatch for 2.5.29.17: expected '${this.expected}'`,
        );
      }

      return;
    }

    // Generic extension handling
    const ext = cert.extension(this.oid);
    if (!ext) {
      throw new PolicyError(`Certificate missing extension ${this.oid}`);
    }

    let got: string | undefined;

    try {
      /*
        ext.valueObj is the ASN.1 object for extnValue.
        For V1 Fulcio:
            OCTET STRING → raw bytes
        For V2 Fulcio:
            OCTET STRING → DER UTF8String
      */

      const valueObj = ext.valueObj;

      // Case 1: DER-wrapped UTF8String (Fulcio V2-style)
      if (valueObj.subs && valueObj.subs.length > 0) {
        const inner = valueObj.subs[0];

        if (inner?.value) {
          got = new TextDecoder().decode(inner.value);
        }
      }

      // Case 2: Raw OCTET STRING (Fulcio V1-style)
      if (!got) {
        got = new TextDecoder().decode(ext.value);
      }
    } catch {
      throw new PolicyError(`Unable to decode extension ${this.oid}`);
    }

    if (!this.claimMatches(got)) {
      throw new PolicyError(
        `Extension ${this.oid} mismatch: got '${got}', expected '${this.expected}'`,
      );
    }
  }
}

class CertFreshnessPolicy implements VerificationPolicy {
  validUntil = 0;
  expired?: WebcatError;
  constructor(private maxAgeSeconds: number) {}

  verify(cert: X509Certificate): void {
    const now = Math.floor(Date.now() / 1000);
    const issued = Math.floor(cert.notBefore.getTime() / 1000);
    const validUntil = issued + this.maxAgeSeconds;

    if (now > validUntil) {
      this.expired = new WebcatError(WebcatErrorCode.Manifest.EXPIRED, [
        String(this.maxAgeSeconds),
        String(issued),
      ]);
      throw new PolicyError(
        `Signing certificate is too old: issued at ${issued}, max age ${this.maxAgeSeconds}s`,
      );
    }
    if (!this.validUntil || this.validUntil > validUntil) {
      this.validUntil = validUntil;
    }
  }
}

// See: https://github.com/sigstore/cosign/issues/2691
// There two way to verify a worflow, check the identity
// which lands us in tricky parsing territory, or verify the
// cert extensions. However, in the latter case we'd need to
// hardcode/support specific extensions and we don't want
// vendor lock-in at this stage, especially given the possible
// bring your own Sigstore approach
// See: https://github.com/tinfoilsh/tinfoil-js/blob/main/packages/verifier/src/sigstore.ts
export async function verifySigstoreManifest(
  enrollment: SigstoreEnrollment,
  manifest: Manifest,
  signatures: SigstoreSignatures,
): Promise<WebcatError | number> {
  const verifier = new SigstoreVerifier();
  await verifier.loadSigstoreRoot(enrollment.trusted_root);

  // Support for legacy identity/issuer format
  /*let effectiveClaims: Record<string, string> = {};

  if (enrollment.claims && Object.keys(enrollment.claims).length > 0) {
    effectiveClaims = enrollment.claims;
  } else {
    // Legacy fallback
    // issuer → Fulcio OIDC issuer extension
    // identity → SAN
    if (
      typeof (enrollment as any).issuer === "string" &&
      typeof (enrollment as any).identity === "string"
    ) {
      effectiveClaims = {
        // SAN (SubjectAlternativeName)
        "2.5.29.17": (enrollment as any).identity,

        // Fulcio OIDC issuer
        // 1.3.6.1.4.1.57264.1.8 is the Fulcio issuer OID
        "1.3.6.1.4.1.57264.1.8": (enrollment as any).issuer,
      };
    }
  }*/

  const claimPolicies: VerificationPolicy[] = [];

  for (const [oid, expected] of Object.entries(enrollment.claims)) {
    claimPolicies.push(new ClaimPolicy(oid, expected));
  }

  // Keep your existing freshness behavior (previously inside IdentityMatch)
  const freshnessPolicy = new CertFreshnessPolicy(enrollment.max_age);
  claimPolicies.push(freshnessPolicy);

  const policy = new AllOf(claimPolicies);

  // signatures must be an array of bundles.
  if (!Array.isArray(signatures)) {
    return new WebcatError(WebcatErrorCode.Bundle.SIGNATURES_MISSING);
  }

  // canonicalize returns null for a manifest it cannot encode.
  const canonical = canonicalize(manifest);
  if (canonical === null) {
    return new WebcatError(WebcatErrorCode.Manifest.VERIFY_FAILED);
  }
  const canonicalized = stringToUint8Array(canonical);

  let verified = false;

  // Does it make sense for this to be an array? Is there cases where the same manifest
  // Could have information of multile bundles, and we care just about one?
  for (const bundle of signatures) {
    try {
      verified = await verifier.verifyArtifactPolicy(
        policy,
        bundle,
        canonicalized,
      );
      if (verified) {
        break;
      }
    } catch (e) {
      console.log(e);
    }
  }

  if (!verified) {
    return (
      freshnessPolicy.expired ??
      new WebcatError(WebcatErrorCode.Manifest.VERIFY_FAILED)
    );
  }

  return freshnessPolicy.validUntil;
}
