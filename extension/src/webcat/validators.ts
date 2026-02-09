import {
  AllOf,
  EXTENSION_OID_OTHERNAME,
  OIDCIssuer,
  PolicyError,
  SigstoreVerifier,
  VerificationPolicy,
  X509Certificate,
} from "@freedomofpress/sigstore-browser";
import { verifyMessageWithCompiledPolicy } from "@freedomofpress/sigsum";
import {
  verifyCosignedTreeHead,
  verifySignedTreeHead,
} from "@freedomofpress/sigsum/dist//crypto";
import {
  evalQuorumBytecode,
  importAndHashAll,
  parseCompiledPolicy,
} from "@freedomofpress/sigsum/dist/compiledPolicy";
import { parseCosignedTreeHead } from "@freedomofpress/sigsum/dist/proof";
import {
  Base64KeyHash,
  CosignedTreeHead,
  KeyHash,
  RawPublicKey,
} from "@freedomofpress/sigsum/dist/types";

import { db } from "./../globals";
import { canonicalize } from "./canonicalize";
import {
  base64UrlToUint8Array,
  stringToUint8Array,
  Uint8ArrayToHex,
} from "./encoding";
import {
  Manifest,
  SigstoreEnrollment,
  SigstoreSignatures,
  SigsumEnrollment,
  SigsumSignatures,
} from "./interfaces/bundle";
import { WebcatError, WebcatErrorCode } from "./interfaces/errors";
import { parseContentSecurityPolicy } from "./parsers";
import { getFQDNSafe, SHA256 } from "./utils";

export function extractAndValidateHeaders(
  details: browser.webRequest._OnHeadersReceivedDetails,
): Map<string, string> | WebcatError {
  // Ensure that response headers exist.
  if (!details.responseHeaders) {
    return new WebcatError(WebcatErrorCode.Headers.MISSING);
  }

  // Define the critical headers we care about.
  const criticalHeaders = new Set(["content-security-policy"]);

  const forbiddenHeaders = new Set([
    // See https://github.com/freedomofpress/webcat/issues/23
    // Furthermore, as reported by TBD there's the risk of TBD
    //"location",
    // See https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Refresh
    // It's just another way to achieve redirects
    "refresh",
    // See https://github.com/freedomofpress/webcat/issues/24
    "link",
  ]);

  // Track seen critical headers to detect duplicates.
  const seenCriticalHeaders = new Set<string>();
  const normalizedHeaders = new Map<string, string>();
  const headers: string[] = [];

  // Loop over each header, normalize the name, and store its value.
  for (const header of details.responseHeaders) {
    if (header.name && header.value) {
      const lowerName = header.name.toLowerCase();
      const value = header.value;

      // Check and block in case of forbidden headers
      // Special case: Location header — allow only relative redirects
      if (lowerName === "location") {
        if (!isSafeRelativeLocation(value)) {
          return new WebcatError(WebcatErrorCode.Headers.LOCATION_EXTERNAL, [
            String(value),
          ]);
        }
      } else if (forbiddenHeaders.has(lowerName)) {
        return new WebcatError(WebcatErrorCode.Headers.FORBIDDEN, [
          String(lowerName),
        ]);
      }

      // Check for duplicates among critical headers.
      if (criticalHeaders.has(lowerName)) {
        if (seenCriticalHeaders.has(lowerName)) {
          return new WebcatError(WebcatErrorCode.Headers.DUPLICATE, [
            String(lowerName),
          ]);
        }
        seenCriticalHeaders.add(lowerName);
      }

      normalizedHeaders.set(lowerName, header.value);
      headers.push(lowerName);
    }
  }

  // Ensure all critical headers are present.
  for (const criticalHeader of criticalHeaders) {
    if (!normalizedHeaders.has(criticalHeader)) {
      return new WebcatError(WebcatErrorCode.Headers.MISSING_CRITICAL, [
        String(criticalHeader),
      ]);
    }
  }

  // Retrieve the Content-Security-Policy (CSP) header (safe to use non-null assertion here based on the check above).
  return normalizedHeaders;
}

export async function validateCSP(
  csp: string,
  fqdn: string,
  valid_sources: Set<string>,
) {
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
    StrictDynamic = "'strict-dynamic",
  }

  enum source_types {
    Hash = "'sha",
    Blob = "blob:",
    Data = "data:",
    EnrolledOrigins = 1,
  }

  // The spec (and thus the parsing function) has to lowercase the directive names
  const parsedCSP = parseContentSecurityPolicy(csp);

  let default_src_is_none = false;
  const default_src = parsedCSP.get(directives.DefaultSrc);

  // Step 1: check default src, which is the default for almost everything.
  // 'self' and 'none' are allowed, but they have different implications and we should tag them
  if (default_src) {
    for (const src of default_src) {
      if (src === source_keywords.None) {
        default_src_is_none = true;
        break;
      } else if (src === source_keywords.Self) {
        // Explicitly allowed for readability
        continue;
      } else {
        throw new Error(
          `Unexpected or non-allowed default-src directive: ${src}`,
        );
      }
    }
  }

  // Step 2: enforce object-src 'none' if default-src is not 'none'
  const object_src = parsedCSP.get(directives.ObjectSrc);
  if (default_src_is_none == false && (!object_src || object_src.length < 1)) {
    throw new Error(
      `${directives.DefaultSrc} is not none, and ${directives.ObjectSrc} is not defined.`,
    );
  } else if (object_src) {
    for (const src of object_src) {
      if (src !== source_keywords.None) {
        throw new Error(`Non-allowed ${directives.ObjectSrc} directive ${src}`);
      }
    }
  }

  async function isSourceAllowed(
    src: string,
    directive: string,
    allowed_keywords: string[],
    allowed_source_types: source_types[],
  ): Promise<boolean> {
    const lower_src = src.toLowerCase();
    if (allowed_keywords.includes(lower_src)) {
      return true;

      // Onion services might do this, we enforce at a higher level
      //} else if (src.includes("http:")) {
      //  throw new Error(`${directive} cannot contain http: sources. `);
    } else if (
      allowed_source_types.includes(source_types.Hash) &&
      src.startsWith(source_types.Hash)
    ) {
      return true;
    } else if (
      allowed_source_types.includes(source_types.Blob) &&
      src.startsWith(source_types.Blob)
    ) {
      return true;
    } else if (
      allowed_source_types.includes(source_types.Data) &&
      src.startsWith(source_types.Data)
    ) {
      return true;
    } else if (
      allowed_source_types.includes(source_types.EnrolledOrigins) &&
      src.includes(".")
    ) {
      let fqdn: string;
      try {
        fqdn = getFQDNSafe(src);
      } catch (e) {
        throw new Error(
          `${directive} value ${src} was parsed as a url but it is not valid: ${e}`,
        );
      }

      if ((await db.getFQDNEnrollment(fqdn)).length !== 0) {
        valid_sources.add(fqdn);
        return true;
      } else {
        throw new Error(
          `${directive} value ${src}, parsed as FQDN: ${fqdn} is not enrolled and thus not allowed.`,
        );
      }
    } else {
      throw new Error(
        `${directive} cannot contain ${src} which is unsupported.`,
      );
    }
  }

  async function validateDirectiveList(
    directive: string,
    list: string[] | undefined,
    default_src_is_none: boolean,
    allowed_keywords: string[],
    allowed_source_types: source_types[],
  ) {
    if (default_src_is_none == false && (!list || list.length < 1)) {
      throw new Error(
        `${directives.DefaultSrc} is not none, and ${directive} is not defined.`,
      );
    }

    if (list) {
      for (const src of list) {
        await isSourceAllowed(
          src,
          directive,
          allowed_keywords,
          allowed_source_types,
        );
      }
    }
  }

  // Step 3: think about scripts
  // Here allowing hash would break the WASM hooking; as we are no longer injecting
  // Via a content_script, but rather at the network level on script files, having embedded
  // JS in HTML page could break the assumptions.

  await validateDirectiveList(
    directives.ScriptSrc,
    parsedCSP.get(directives.ScriptSrc),
    default_src_is_none,
    [
      source_keywords.None,
      source_keywords.Self,
      source_keywords.WasmUnsafeEval,
    ],
    [],
  );

  await validateDirectiveList(
    directives.ScriptSrcElem,
    parsedCSP.get(directives.ScriptSrcElem),
    default_src_is_none || parsedCSP.has(directives.ScriptSrc),
    [
      source_keywords.None,
      source_keywords.Self,
      source_keywords.WasmUnsafeEval,
    ],
    [],
  );

  // Step 4: validate style-src
  // TODO credit for -elem tags
  await validateDirectiveList(
    directives.StyleSrc,
    parsedCSP.get(directives.StyleSrc),
    default_src_is_none,
    [
      source_keywords.None,
      source_keywords.Self,
      // TODO eventually these 2 should disappear
      source_keywords.UnsafeInline,
      source_keywords.UnsafeHashes,
    ],
    [source_types.Hash],
  );

  await validateDirectiveList(
    directives.StyleSrcElem,
    parsedCSP.get(directives.StyleSrcElem),
    default_src_is_none || parsedCSP.has(directives.StyleSrc),
    [
      source_keywords.None,
      source_keywords.Self,
      source_keywords.UnsafeInline,
      source_keywords.UnsafeHashes,
    ],
    [source_types.Hash],
  );

  // Step 5: validate frame-src and child-src. They should follow the same policy and in theory one overrides the other
  // but it depends on the CSP level so we'll check everything
  const child_src = parsedCSP.get(directives.ChildSrc);
  const frame_src = parsedCSP.get(directives.FrameSrc);
  if (
    default_src_is_none == false &&
    (!child_src || child_src.length < 1) &&
    (!frame_src || frame_src.length < 1)
  ) {
    throw new Error(
      `${directives.DefaultSrc} is not none, and neither ${directives.FrameSrc} or ${directives.ChildSrc} are defined.`,
    );
  } else if (child_src || frame_src) {
    if (child_src) {
      for (const src of child_src) {
        await isSourceAllowed(
          src,
          directives.ChildSrc,
          [source_keywords.None, source_keywords.Self],
          // You can iframe from a blob, and that will be either HTMl or include authenticated script
          // Cause the script src is inherited or enforced in all frames, also the hook injection is inherited by allFrames
          [source_types.Blob, source_types.Data, source_types.EnrolledOrigins],
        );
      }
    }

    if (frame_src) {
      for (const src of frame_src) {
        await isSourceAllowed(
          src,
          directives.FrameSrc,
          [source_keywords.None, source_keywords.Self],
          // Same as for child src
          [source_types.Blob, source_types.Data, source_types.EnrolledOrigins],
        );
      }
    }
  }

  const worker_src = parsedCSP.get(directives.WorkerSrc);
  if (default_src_is_none == false && (!worker_src || worker_src.length < 1)) {
    throw new Error(
      `${directives.DefaultSrc} is not none, and ${directives.WorkerSrc} is not defined.`,
    );
  } else if (worker_src) {
    for (const src of worker_src) {
      await isSourceAllowed(
        src,
        directives.WorkerSrc,
        [source_keywords.None, source_keywords.Self],
        [],
      );
    }
  }
}

export function isSafeRelativeLocation(value: string): boolean {
  value = value.trim();

  // No scheme, no protocol-relative, no backslashes
  return (
    (value.startsWith("/") ||
      value.startsWith("../") ||
      value.startsWith("./")) &&
    !value.startsWith("//") &&
    !value.includes("\\")
  );
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

export function validateProtocolAndPort(urlobj: URL): boolean {
  if (
    !["80", "443", ""].includes(urlobj.port) ||
    !["http:", "https:"].includes(urlobj.protocol)
  ) {
    return false;
  } else {
    return true;
  }
}

export function enforceHTTPS(urlobj: URL): string | undefined {
  if (
    urlobj.protocol !== "https:" &&
    urlobj.hostname.substring(urlobj.hostname.lastIndexOf(".")) !== ".onion"
  ) {
    urlobj.protocol = "https:";
    return urlobj.toString();
  }
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

  // Issuer is mandatory (OIDC issuer / Fulcio issuer)
  if (typeof enrollment.issuer !== "string" || enrollment.issuer.length === 0) {
    return new WebcatError(
      WebcatErrorCode.Enrollment.IDENTITY_ISSUER_MALFORMED,
      [String(enrollment.issuer)],
    );
  }

  const hasIdentity =
    typeof enrollment.identity === "string" && enrollment.identity.length > 0;

  if (!hasIdentity) {
    return new WebcatError(WebcatErrorCode.Enrollment.IDENTITY_REQUIRED);
  }

  if (
    typeof enrollment.max_age !== "number" ||
    !Number.isFinite(enrollment.max_age)
  ) {
    return new WebcatError(WebcatErrorCode.Enrollment.MAX_AGE_MALFORMED);
  }

  return null;
}

export function validateManifest(manifest: Manifest): WebcatError | null {
  if (!manifest.files || Object.keys(manifest.files).length < 1) {
    return new WebcatError(WebcatErrorCode.Manifest.FILES_MISSING);
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
    return new WebcatError(WebcatErrorCode.Manifest.DEFAULT_FALLBACK_MISSING);
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
): Promise<WebcatError | null> {
  const canonicalized = stringToUint8Array(canonicalize(manifest));

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

  return null;
}

// Prepare a VerificationPolicy to do the following:
// - If the SAN is a url, we guess it's a workflow and do prefix matching
// - If the SAN is an email, we want an exact match there
// SECURITY TODO: The logic is fuzzy here, and automatic fallbacks
// with partial matches are a really bad recipe. However, we either lock-in GitHub
// or we add more metadata to enrollment?
export class IdentityMatch implements VerificationPolicy {
  private expected: string;
  private issuerPolicy: OIDCIssuer | null;
  private maxAgeSeconds: number;

  constructor(options: {
    identity: string;
    issuer: string;
    maxAgeSeconds: number;
  }) {
    this.expected = options.identity;
    this.issuerPolicy = options.issuer ? new OIDCIssuer(options.issuer) : null;
    this.maxAgeSeconds = options.maxAgeSeconds;
  }

  verify(cert: X509Certificate): void {
    // 1. Issuer verification
    if (this.issuerPolicy) {
      this.issuerPolicy.verify(cert);
    }

    // 2. Identity verification
    const sanExt = cert.extSubjectAltName;
    if (!sanExt) {
      throw new PolicyError(
        "Certificate does not contain SubjectAlternativeName extension",
      );
    }

    let uriIdentity: string | null = null;

    if (sanExt.uri) {
      uriIdentity = sanExt.uri;
    }

    const otherName = sanExt.otherName(EXTENSION_OID_OTHERNAME);
    if (otherName) {
      if (uriIdentity && otherName !== uriIdentity) {
        throw new PolicyError("Certificate contains multiple URI identities");
      }
      uriIdentity = otherName;
    }

    if (!uriIdentity) {
      throw new PolicyError(
        "Certificate does not contain a URI-based identity SAN",
      );
    }

    if (!uriIdentity.startsWith(this.expected)) {
      throw new PolicyError(
        `URI identity "${uriIdentity}" does not match expected prefix "${this.expected}"`,
      );
    }

    // 3. Freshness enforcement
    // This is not semantically the same as Sigsum. Sigsum fetches a trusted timestamp
    // and includes it in the message before signing. Here we validate
    // the freshness of the identity issuance.
    // TODO
    const now = Math.floor(Date.now() / 1000);
    const issued = Math.floor(cert.notBefore.getTime() / 1000);

    if (now - issued > this.maxAgeSeconds) {
      throw new PolicyError(
        `Signing certificate is too old: issued at ${issued}, max age ${this.maxAgeSeconds}s`,
      );
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
): Promise<WebcatError | null> {
  const verifier = new SigstoreVerifier();
  await verifier.loadSigstoreRoot(enrollment.trusted_root);

  const policy = new AllOf([
    new IdentityMatch({
      issuer: enrollment.issuer, // e.g. https://token.actions.githubusercontent.com
      identity: enrollment.identity, // e.g. https://github.com/org/repo/
      maxAgeSeconds: enrollment.max_age,
    }),
  ]);

  // Compute manifest digest (same role as `digest` in verifyAttestation)
  const manifestHash = await Uint8ArrayToHex(
    new Uint8Array(await SHA256(canonicalize(manifest))),
  );

  let verified = false;

  // Does it make sense for this to be an array? Is there cases where the same manifest
  // Could have information of multile bundles, and we care just about one?
  for (const bundle of signatures) {
    if (bundle.dsseEnvelope) {
      try {
        const { payloadType, payload } = await verifier.verifyDsse(
          bundle,
          policy,
        );

        if (payloadType !== "application/vnd.in-toto+json") {
          throw new Error(
            `Unsupported payload type: ${payloadType}. Only supports In-toto.`,
          );
        }

        const statement = JSON.parse(new TextDecoder().decode(payload));

        const subject = statement.subject?.[0];
        const attestedDigest = subject?.digest?.sha256;

        if (!attestedDigest) {
          throw new Error(
            "Attestation does not contain a SHA-256 subject digest",
          );
        }

        if (attestedDigest !== manifestHash) {
          throw new Error(
            `Manifest digest mismatch. Expected: ${manifestHash}, Got: ${attestedDigest}`,
          );
        }

        // We need at least one valid bundle that matches the policy,
        // but we don't want to quit if one doesn't
        // TODO SECURITY: better logic here
        verified = true;
        break;
      } catch (e) {
        console.log(e);
        continue;
      }
    } else {
      try {
        verified = await verifier.verifyArtifact(
          enrollment.identity,
          enrollment.issuer,
          bundle,
          stringToUint8Array(canonicalize(manifest)),
        );
      } catch (e) {
        console.log(e);
      }
    }
  }

  if (!verified) {
    return new WebcatError(WebcatErrorCode.Manifest.VERIFY_FAILED);
  }

  return null;
}
