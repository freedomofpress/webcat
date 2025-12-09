import { RawPublicKey } from "@freedomofpress/sigsum/dist/types";
import { verifyMessageWithCompiledPolicy } from "@freedomofpress/sigsum/dist/verify";

import { bundle_name, bundle_prev_name } from "../../config";
import { db } from "../../globals";
import { canonicalize } from "../canonicalize";
import { base64UrlToUint8Array, stringToUint8Array } from "../encoding";
import { headersListener, requestListener } from "../listeners";
import { arraysEqual } from "../utils";
import { SHA256 } from "../utils";
import {
  validateCSP,
  witnessTimestampsFromCosignedTreeHead,
} from "../validators";
import { Bundle, Enrollment, Manifest, Signatures } from "./bundle";
import { WebcatError, WebcatErrorCode } from "./errors";

export class OriginStateHolder {
  constructor(
    public current:
      | OriginStateBase
      | OriginStateInitial
      | OriginStateVerifiedEnrollment
      | OriginStateVerifiedManifest
      | OriginStateFailed,
  ) {
    const base = `${current.scheme}//${current.fqdn}:${current.port}/`;
    current.bundlePromise = fetch(`${base}/${bundle_name}`, {
      cache: "no-store",
    });
    current.bundlePrevPromise = fetch(`${base}/${bundle_prev_name}`, {
      cache: "no-store",
    });
  }

  // Remove the listeners if the class det destroyed (called on cache eviction)
  destructor(): void {
    // Remove the Mozilla API listeners
    browser.webRequest.onBeforeRequest.removeListener(
      this.current.onBeforeRequest,
    );
    browser.webRequest.onHeadersReceived.removeListener(
      this.current.onHeadersReceived,
    );
  }
}

// The OriginState class caches origins and assumes safe defaults. We assume we are enrolled and nothing is verified.
export abstract class OriginStateBase {
  abstract status:
    | "request_sent"
    | "verified_enrollment"
    | "verified_manifest"
    | "failed";
  public readonly scheme: string;
  public readonly port: string;
  public readonly fqdn: string;
  public readonly enrollment_hash: Uint8Array;
  public bundlePromise?: Promise<Response>;
  public bundlePrevPromise?: Promise<Response>;
  public bundle_source: "current" | "previous" = "current";
  public references: number;
  public bundle?: Bundle;
  public readonly enrollment?: Enrollment;
  public readonly manifest?: Manifest;
  public readonly valid_signers?: Set<string>;
  public readonly valid_sources?: Set<string>;
  public readonly delegation?: string;

  // Per origin function wrappers: the extension API does not support registering
  // the same listener multiple times with different rules. We thus want a wrapper
  // listener per every origin for their own intercepting function
  public onBeforeRequest: (
    details: browser.webRequest._OnBeforeRequestDetails,
  ) => Promise<browser.webRequest.BlockingResponse>;
  public onHeadersReceived: (
    details: browser.webRequest._OnHeadersReceivedDetails,
  ) => Promise<browser.webRequest.BlockingResponse>;

  // Due to list logic, we support only one app per domain, and that should be a privileged one
  // But that is enforced in request.ts
  constructor(
    scheme: string,
    port: string,
    fqdn: string,
    enrollment_hash: Uint8Array,
  ) {
    this.scheme = scheme;
    this.port = port;
    this.fqdn = fqdn;
    this.enrollment_hash = enrollment_hash;
    this.references = 1;

    this.onBeforeRequest = (details) => requestListener(details);
    this.onHeadersReceived = (details) => headersListener(details);
  }

  public async awaitBundle(source: "current" | "previous") {
    // If we already have a bundle, consider it done
    if (this.bundle && this.bundle_source === source) {
      return;
    }
    // If bundlePromise was awaited before and cached a failure result,
    // we don't want to re-fetch, so detect that. It should never happen
    let promise;
    if (source == "current") {
      promise = this.bundlePromise;
    } else if (source == "previous") {
      promise = this.bundlePrevPromise;
    }

    if (!promise) {
      return new OriginStateFailed(
        this,
        new WebcatError(WebcatErrorCode.Fetch.FETCH_PROMISE_MISSING),
      );
    }
    const bundleResponse = await promise;
    if (bundleResponse.ok !== true) {
      return new OriginStateFailed(
        this,
        new WebcatError(WebcatErrorCode.Fetch.FETCH_ERROR),
      );
    }
    const bundle_data: Bundle = (await bundleResponse.json()) as Bundle;
    if (!bundle_data.enrollment) {
      return new OriginStateFailed(
        this,
        new WebcatError(WebcatErrorCode.Bundle.ENROLLMENT_MISSING),
      );
    }
    if (!bundle_data.manifest) {
      return new OriginStateFailed(
        this,
        new WebcatError(WebcatErrorCode.Bundle.MANIFEST_MISSING),
      );
    }
    if (!bundle_data.signatures) {
      return new OriginStateFailed(
        this,
        new WebcatError(WebcatErrorCode.Bundle.SIGNATURES_MISSING),
      );
    }
    this.bundle = bundle_data;
    this.bundle_source = source;
  }
}

export class OriginStateFailed extends OriginStateBase {
  public readonly status = "failed" as const;
  public readonly error: WebcatError;

  constructor(prev: OriginStateBase, error: WebcatError) {
    super(prev.scheme, prev.port, prev.fqdn, prev.enrollment_hash);
    Object.assign(this, prev);
    // We must set it again because we are copying
    this.status = "failed" as const;
    this.error = error;
  }
}

export class OriginStateInitial extends OriginStateBase {
  public status = "request_sent" as const;
  public bundle?: Bundle;

  constructor(
    scheme: string,
    port: string,
    fqdn: string,
    enrollment_hash: Uint8Array,
  ) {
    super(scheme, port, fqdn, enrollment_hash);
  }

  public async verifyDelegation(delegation: string): Promise<boolean> {
    const delegation_hash = await db.getFQDNEnrollment(delegation);
    return (
      delegation_hash && arraysEqual(delegation_hash, this.enrollment_hash)
    );
  }

  public async verifyEnrollment(
    enrollment?: Enrollment,
    delegation?: string,
  ): Promise<OriginStateVerifiedEnrollment | OriginStateFailed> {
    let verified_delegation;
    if (delegation && (await this.verifyDelegation(delegation))) {
      verified_delegation = delegation;
    }

    // Enrollment info can be fetched from a manifest bundle,
    // or we should support supplying it differently, such is in http headers

    if (!enrollment) {
      const res = await this.awaitBundle("current");
      if (res instanceof OriginStateFailed) {
        return res;
      }
      // We can assert here because the check is guaranteed in awaitBundle
      // eslint-disable-next-line
      enrollment = this.bundle!.enrollment;
    }

    const canonicalized = stringToUint8Array(canonicalize(enrollment));
    const canonicalized_hash = new Uint8Array(await SHA256(canonicalized));

    // If it doesn't match, stop early
    const match = arraysEqual(this.enrollment_hash, canonicalized_hash);
    // In this case, we already tried both bundles and we should bail
    if (!match && this.bundle_source == "previous") {
      return new OriginStateFailed(
        this,
        new WebcatError(WebcatErrorCode.Enrollment.MISMATCH),
      );
      // Othweise we shpould await the previous
    } else if (!match && this.bundle_source == "current") {
      const res = await this.awaitBundle("previous");
      // If we are here and the fetch fails, its fatal
      if (res instanceof OriginStateFailed) {
        return res;
      }
      // Let's use the enrollment fallback

      const canonicalized_prev = stringToUint8Array(
        // eslint-disable-next-line
        canonicalize(this.bundle!.enrollment),
      );
      const canonicalized_hash_prev = new Uint8Array(
        await SHA256(canonicalized_prev),
      );
      // If this also fails it's fatal
      if (!arraysEqual(this.enrollment_hash, canonicalized_hash_prev)) {
        return new OriginStateFailed(
          this,
          new WebcatError(WebcatErrorCode.Enrollment.MISMATCH),
        );
      }
    }

    if (typeof enrollment.policy !== "string") {
      return new OriginStateFailed(
        this,
        new WebcatError(WebcatErrorCode.Enrollment.POLICY_MALFORMED),
      );
    }
    if (enrollment.policy.length === 0 || enrollment.policy.length > 8192) {
      return new OriginStateFailed(
        this,
        new WebcatError(WebcatErrorCode.Enrollment.POLICY_LENGTH),
      );
    }

    if (!Array.isArray(enrollment.signers)) {
      return new OriginStateFailed(
        this,
        new WebcatError(WebcatErrorCode.Enrollment.SIGNERS_MALFORMED),
      );
    }

    if (enrollment.signers.length === 0) {
      return new OriginStateFailed(
        this,
        new WebcatError(WebcatErrorCode.Enrollment.SIGNERS_EMPTY),
      );
    }

    for (const key of enrollment.signers) {
      if (typeof key !== "string") {
        return new OriginStateFailed(
          this,
          new WebcatError(WebcatErrorCode.Enrollment.SIGNERS_KEY_MALFORMED, [
            String(key),
          ]),
        );
      }
    }

    if (
      typeof enrollment.threshold !== "number" ||
      !Number.isInteger(enrollment.threshold) ||
      enrollment.threshold < 1
    ) {
      return new OriginStateFailed(
        this,
        new WebcatError(WebcatErrorCode.Enrollment.THRESHOLD_MALFORMED),
      );
    }

    if (enrollment.threshold > enrollment.signers.length) {
      return new OriginStateFailed(
        this,
        new WebcatError(WebcatErrorCode.Enrollment.THRESHOLD_IMPOSSIBLE),
      );
    }

    if (
      typeof enrollment.max_age !== "number" ||
      !Number.isFinite(enrollment.max_age)
    ) {
      return new OriginStateFailed(
        this,
        new WebcatError(WebcatErrorCode.Enrollment.MAX_AGE_MALFORMED),
      );
    }

    //const ONE_YEAR_SECONDS = 365 * 24 * 60 * 60;
    //if (enrollment.max_age <= 0 || enrollment.max_age > ONE_YEAR_SECONDS) {
    //  return fail("max_age must be >0 and <1 year (seconds)");
    //}

    // we probably don't care about validating it in the client as it is useful for monitoring
    //if (typeof enrollment.cas_url !== "string") {
    //  return fail("cas_url must be a string");
    //}

    // TODO: we currently use the orginal raw enrollment data structure
    // However we should import signing keys once as cryptokeys and
    // parse the compiled sigsum policy once here instead of doing that
    // at every verification. Currently the sigsum-ts lib does not support that
    // and maybe more abstraction there would be useful
    const next = new OriginStateVerifiedEnrollment(
      this,
      enrollment,
      verified_delegation,
    );
    next.bundlePromise = this.bundlePromise;
    return next;
  }
}

export class OriginStateVerifiedEnrollment extends OriginStateBase {
  public readonly status = "verified_enrollment" as const;
  public readonly enrollment: Enrollment;
  public readonly delegation?: string | undefined;
  public bundle?: Bundle;

  constructor(
    prev: OriginStateInitial,
    enrollment: Enrollment,
    delegation: string | undefined,
  ) {
    super(prev.scheme, prev.port, prev.fqdn, prev.enrollment_hash);
    this.bundle = prev.bundle;
    this.bundlePromise = prev.bundlePromise;
    this.onBeforeRequest = prev.onBeforeRequest;
    this.onHeadersReceived = prev.onHeadersReceived;
    this.references = prev.references;
    this.enrollment = enrollment;
    this.delegation = delegation;
  }

  public async verifyManifest(
    manifest?: Manifest,
    signatures?: Signatures,
  ): Promise<OriginStateVerifiedManifest | OriginStateFailed> {
    // Manifest info can be fetched from a manifest bundle,
    // or we should support supplying it differently
    // If enrollment information is passed from headers or another source, then we do not support
    // a fallbackm bundle at the moment
    if (!manifest || !signatures) {
      const res = await this.awaitBundle("current");
      if (res instanceof OriginStateFailed) {
        return res;
      }
      // awaitBundle checks already that manifest exists
      // eslint-disable-next-line
      manifest = this.bundle!.manifest;
      // eslint-disable-next-line
      signatures = this.bundle!.signatures;
    }

    const canonicalized = stringToUint8Array(canonicalize(manifest));

    // The purpose of cloning the original list of signers is to have logic to ensure
    // that each signers can at most sign once. Since we are dealing with a lot of
    // transformations (hex, b64, etc) and any of these can have malleability, we want to
    // avoid a scenario where the same signature but with a different public key
    // encoding is counted twice. By removing a signer from the set of possible signers
    // we shold prevent this systematically.
    const remainingSigners = new Set(this.enrollment.signers);
    let validCount = 0;

    for (const pubKey of Object.keys(signatures)) {
      if (remainingSigners.has(pubKey)) {
        try {
          // Verify using Sigsum using:
          // - The signer public key
          // - The compiled policy in the enrollment metadata
          // - The signature and Sigsum proof associated
          await verifyMessageWithCompiledPolicy(
            canonicalized,
            new RawPublicKey(base64UrlToUint8Array(pubKey)),
            base64UrlToUint8Array(this.enrollment.policy),
            signatures[pubKey],
          );
        } catch (e) {
          return new OriginStateFailed(
            this,
            new WebcatError(WebcatErrorCode.Manifest.VERIFY_FAILED, [
              String(e),
            ]),
          );
        }
        remainingSigners.delete(pubKey);
        validCount++;
      }
    }

    // Not enough signatures to verify the manifest
    if (validCount < this.enrollment.threshold) {
      return new OriginStateFailed(
        this,
        new WebcatError(WebcatErrorCode.Manifest.THRESHOLD_UNSATISFIED, [
          String(validCount),
          String(this.enrollment.threshold),
        ]),
      );
    }

    if (!manifest.timestamp) {
      return new OriginStateFailed(
        this,
        new WebcatError(WebcatErrorCode.Manifest.TIMESTAMP_MISSING),
      );
    }

    let timestamps;
    try {
      timestamps = await witnessTimestampsFromCosignedTreeHead(
        base64UrlToUint8Array(this.enrollment.policy),
        manifest.timestamp,
      );
    } catch (e) {
      return new OriginStateFailed(
        this,
        new WebcatError(WebcatErrorCode.Manifest.TIMESTAMP_VERIFY_FAILED, [
          String(e),
        ]),
      );
    }

    const timestamp = timestamps.sort((a, b) => a - b)[
      Math.floor(timestamps.length / 2)
    ];

    const now = Math.floor(Date.now() / 1000);

    if (now - timestamp > this.enrollment.max_age) {
      return new OriginStateFailed(
        this,
        new WebcatError(WebcatErrorCode.Manifest.EXPIRED, [
          String(this.enrollment.max_age),
          String(timestamp),
        ]),
      );
    }

    // A manifest with no files should not exists
    if (!manifest.files || Object.keys(manifest.files).length < 1) {
      return new OriginStateFailed(
        this,
        new WebcatError(WebcatErrorCode.Manifest.FILES_MISSING),
      );
    }

    // If there is no default CSP than the manifest is incomplete
    if (!manifest.default_csp) {
      return new OriginStateFailed(
        this,
        new WebcatError(WebcatErrorCode.Manifest.DEFAULT_CSP_MISSING),
      );
    }

    // If there is no default index or fallback
    if (!manifest.default_index) {
      return new OriginStateFailed(
        this,
        new WebcatError(WebcatErrorCode.Manifest.DEFAULT_INDEX_MISSING),
      );
    }

    if (!manifest.default_fallback) {
      return new OriginStateFailed(
        this,
        new WebcatError(WebcatErrorCode.Manifest.DEFAULT_FALLBACK_MISSING),
      );
    }

    // The file referenced by default_index must be in files
    if (!manifest.files["/" + manifest.default_index]) {
      return new OriginStateFailed(
        this,
        new WebcatError(WebcatErrorCode.Manifest.DEFAULT_INDEX_MISSING_FILE),
      );
    }

    // The file referenced by default_fallback must be in files
    if (!manifest.files[manifest.default_fallback]) {
      return new OriginStateFailed(
        this,
        new WebcatError(WebcatErrorCode.Manifest.DEFAULT_FALLBACK_MISSING),
      );
    }

    if (!manifest.wasm) {
      return new OriginStateFailed(
        this,
        new WebcatError(WebcatErrorCode.Manifest.WASM_MISSING),
      );
    }

    // ValidateCSP will populate this based on hosts presents in both
    // the CSP policies specified AND the enrollment list
    // If an enrolled CSP policy has non-enrolled hosts, then it will throw
    const valid_sources: Set<string> = new Set();

    // Validate the default CSP
    try {
      await validateCSP(manifest.default_csp, this.fqdn, valid_sources);
    } catch (e) {
      //return new OriginStateFailed(this, `failed parsing default_csp: ${e}`);
      return new OriginStateFailed(
        this,
        new WebcatError(WebcatErrorCode.Manifest.DEFAULT_CSP_INVALID, [
          String(e),
        ]),
      );
    }

    // Validate all extra CSP, it should also fill all the sources
    for (const path in manifest.extra_csp) {
      if (manifest.extra_csp.hasOwnProperty(path)) {
        const csp = manifest.extra_csp[path];
        try {
          await validateCSP(csp, this.fqdn, valid_sources);
        } catch (e) {
          return new OriginStateFailed(
            this,
            new WebcatError(WebcatErrorCode.Manifest.EXTRA_CSP_INVALID, [
              String(e),
            ]),
          );
        }
      } else {
        return new OriginStateFailed(
          this,
          new WebcatError(WebcatErrorCode.Manifest.EXTRA_CSP_MALFORMED, [
            String(path),
          ]),
        );
      }
    }
    const next = new OriginStateVerifiedManifest(this, manifest, valid_sources);
    next.bundlePromise = this.bundlePromise;
    return next;
  }
}

export class OriginStateVerifiedManifest extends OriginStateBase {
  public readonly status = "verified_manifest" as const;
  public readonly delegation?: string | undefined;
  public readonly enrollment: Enrollment;
  public readonly manifest: Manifest;
  public readonly valid_sources: Set<string> = new Set();

  constructor(
    prev: OriginStateVerifiedEnrollment,
    manifest: Manifest,
    valid_sources: Set<string>,
  ) {
    super(prev.scheme, prev.port, prev.fqdn, prev.enrollment_hash);
    this.bundle = prev.bundle;
    this.bundlePromise = prev.bundlePromise;
    this.onBeforeRequest = prev.onBeforeRequest;
    this.onHeadersReceived = prev.onHeadersReceived;
    this.references = prev.references;
    this.enrollment = prev.enrollment;
    this.manifest = manifest;
    this.valid_sources = valid_sources;
    this.delegation = prev.delegation;
  }

  public verifyCSP(csp: string, pathname: string) {
    const extraCSP = this.manifest.extra_csp || {};
    const defaultCSP = this.manifest.default_csp;

    const effectivePath =
      pathname === "/" ? this.manifest.default_index : pathname;

    // Try direct match first (exact path used in extra_csp)
    if (extraCSP[effectivePath]) {
      return csp === extraCSP[effectivePath];
    }

    // Otherwise, try longest-prefix match
    let bestMatch: string | null = null;
    let bestMatchLength = 0;

    for (const prefix in extraCSP) {
      if (effectivePath.startsWith(prefix) && prefix.length > bestMatchLength) {
        bestMatch = prefix;
        bestMatchLength = prefix.length;
      }
    }

    const correctCSP = bestMatch ? extraCSP[bestMatch] : defaultCSP;

    return csp === correctCSP;
  }
}
