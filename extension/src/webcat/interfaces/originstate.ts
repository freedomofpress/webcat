import { bundle_name, bundle_prev_name } from "../../config";
import { db } from "../../globals";
import { canonicalize } from "../canonicalize";
import { stringToUint8Array } from "../encoding";
import { headersListener, requestListener } from "../listeners";
import { arraysEqual } from "../utils";
import { SHA256 } from "../utils";
import { validateCSP, validateSigstoreEnrollment } from "../validators";
import {
  validateManifest,
  validateSigsumEnrollment,
  verifySigstoreManifest,
  verifySigsumManifest,
} from "../validators";
import {
  Bundle,
  Enrollment,
  EnrollmentTypes,
  Manifest,
  SigstoreSignatures,
  SigsumSignatures,
} from "./bundle";
import { WebcatError, WebcatErrorCode } from "./errors";

type BundleFetch = {
  promise: Promise<Response>;
  error?: WebcatError;
  value?: Bundle;
};

export class BundleFetcher implements Iterable<BundleFetch> {
  public readonly current: BundleFetch;
  public readonly previous: BundleFetch;

  constructor(base: string) {
    this.current = {
      promise: fetch(`${base}${bundle_name}`, {
        cache: "no-store",
      }),
    };

    this.previous = {
      promise: fetch(`${base}${bundle_prev_name}`, {
        cache: "no-store",
      }),
    };
  }

  *[Symbol.iterator](): IterableIterator<BundleFetch> {
    yield this.current;
    yield this.previous;
  }

  public async awaitAll(): Promise<void> {
    for (const slot of this) {
      if (slot.value || slot.error) {
        continue;
      }

      let response: Response;
      try {
        response = await slot.promise;
      } catch {
        slot.error = new WebcatError(WebcatErrorCode.Fetch.FETCH_ERROR);
        continue;
      }

      if (!response.ok) {
        slot.error = new WebcatError(WebcatErrorCode.Fetch.FETCH_ERROR);
        continue;
      }

      let bundle: Bundle;
      try {
        bundle = (await response.json()) as Bundle;
      } catch {
        slot.error = new WebcatError(WebcatErrorCode.Bundle.MALFORMED);
        continue;
      }

      if (!bundle.enrollment) {
        slot.error = new WebcatError(WebcatErrorCode.Bundle.ENROLLMENT_MISSING);
        continue;
      }

      if (!bundle.manifest) {
        slot.error = new WebcatError(WebcatErrorCode.Bundle.MANIFEST_MISSING);
        continue;
      }

      if (!bundle.signatures) {
        slot.error = new WebcatError(WebcatErrorCode.Bundle.SIGNATURES_MISSING);
        continue;
      }

      slot.value = bundle;
    }
  }
}

export class OriginStateHolder {
  constructor(
    public current:
      | OriginStateBase
      | OriginStateInitial
      | OriginStateVerifiedEnrollment
      | OriginStateVerifiedManifest
      | OriginStateFailed,
  ) {
    // Empty for now
  }

  destructor(): void {
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
  public fetcher: BundleFetcher;
  public bundle?: Bundle;
  public references: number;
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
    fetcher: BundleFetcher,
    scheme: string,
    port: string,
    fqdn: string,
    enrollment_hash: Uint8Array,
  ) {
    this.fetcher = fetcher;
    this.scheme = scheme;
    this.port = port;
    this.fqdn = fqdn;
    this.enrollment_hash = enrollment_hash;
    this.references = 1;

    this.onBeforeRequest = (details) => requestListener(details);
    this.onHeadersReceived = (details) => headersListener(details);
  }
}

export class OriginStateFailed extends OriginStateBase {
  public readonly status = "failed" as const;
  public readonly error: WebcatError;

  constructor(prev: OriginStateBase, error: WebcatError) {
    super(
      prev.fetcher,
      prev.scheme,
      prev.port,
      prev.fqdn,
      prev.enrollment_hash,
    );
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
    fetcher: BundleFetcher,
    scheme: string,
    port: string,
    fqdn: string,
    enrollment_hash: Uint8Array,
  ) {
    super(fetcher, scheme, port, fqdn, enrollment_hash);
  }

  public async verifyDelegation(delegation: string): Promise<boolean> {
    const delegation_hash = await db.getFQDNEnrollment(delegation);
    return (
      delegation_hash && arraysEqual(delegation_hash, this.enrollment_hash)
    );
  }

  // This functiont ries to verify the enrollment information against the value in the local list
  // It will also return errors while fetching the bundles (though they are generated in awaitBundles)
  // and tell the next stages whether they should use the current or the previous bundle
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
      // It could mismatch because our list is outdated, but it should exists nevertheless
      if (!this.fetcher.current.value) {
        // eslint-disable-next-line
        return new OriginStateFailed(this, this.fetcher.current.error!);
      }

      // We can assert here because the check is guaranteed in awaitBundle

      enrollment = this.fetcher.current.value.enrollment;
    }

    const canonicalized = stringToUint8Array(canonicalize(enrollment));
    const canonicalized_hash = new Uint8Array(await SHA256(canonicalized));

    // If it doesn't match, stop early
    const match = arraysEqual(this.enrollment_hash, canonicalized_hash);
    // In this case, we already tried both bundles and we should bail
    // Or we got direct enrollment passed, and we shpuldn't fallback automatically
    if (match) {
      this.bundle = this.fetcher.current.value;
    } else {
      // If we are here, and the previous fetch failed, we fail on MISMATCH
      // because it means the main enrollment MISMATCHED and there's no fallback
      if (!this.fetcher.previous.value) {
        return new OriginStateFailed(
          this,
          new WebcatError(WebcatErrorCode.Enrollment.MISMATCH),
        );
      }
      enrollment = this.fetcher.previous.value.enrollment;

      const canonicalized_prev = stringToUint8Array(canonicalize(enrollment));
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
      this.bundle = this.fetcher.previous.value;
    }

    let err: WebcatError | null = null;

    if (enrollment.type === EnrollmentTypes.Sigsum) {
      err = validateSigsumEnrollment(enrollment);
    } else if (enrollment.type === EnrollmentTypes.Sigstore) {
      err = validateSigstoreEnrollment(enrollment);
    } else {
      err = new WebcatError(WebcatErrorCode.Enrollment.TYPE_INVALID);
    }

    if (err) {
      return new OriginStateFailed(this, err);
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
    return new OriginStateVerifiedEnrollment(
      this,
      enrollment,
      verified_delegation,
    );
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
    super(
      prev.fetcher,
      prev.scheme,
      prev.port,
      prev.fqdn,
      prev.enrollment_hash,
    );
    this.onBeforeRequest = prev.onBeforeRequest;
    this.onHeadersReceived = prev.onHeadersReceived;
    this.references = prev.references;
    this.enrollment = enrollment;
    this.delegation = delegation;
    this.bundle = prev.bundle;
  }

  public async verifyManifest(
    manifest?: Manifest,
    signatures?: SigsumSignatures | SigstoreSignatures,
  ): Promise<OriginStateVerifiedManifest | OriginStateFailed> {
    // Manifest info can be fetched from a manifest bundle,
    // or we should support supplying it differently
    // If enrollment information is passed from headers or another source, then we do not support
    // a fallback bundle at the moment
    if (!manifest || !signatures) {
      // awaitBundle checks already that manifest exists
      // eslint-disable-next-line
      manifest = this.bundle!.manifest;
      // eslint-disable-next-line
      signatures = this.bundle!.signatures;
    }

    let verify_error: WebcatError | null = null;

    switch (this.enrollment.type) {
      case EnrollmentTypes.Sigsum:
        verify_error = await verifySigsumManifest(
          this.enrollment,
          manifest,
          signatures as SigsumSignatures,
        );
        break;

      case EnrollmentTypes.Sigstore:
        verify_error = await verifySigstoreManifest(
          this.enrollment,
          manifest,
          signatures as SigstoreSignatures,
        );
        break;

      default:
        verify_error = new WebcatError(WebcatErrorCode.Enrollment.TYPE_INVALID);
    }

    if (verify_error) {
      return new OriginStateFailed(this, verify_error);
    }

    const format_error = validateManifest(manifest);
    if (format_error) {
      return new OriginStateFailed(this, format_error);
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
    super(
      prev.fetcher,
      prev.scheme,
      prev.port,
      prev.fqdn,
      prev.enrollment_hash,
    );
    this.onBeforeRequest = prev.onBeforeRequest;
    this.onHeadersReceived = prev.onHeadersReceived;
    this.references = prev.references;
    this.enrollment = prev.enrollment;
    this.manifest = manifest;
    this.valid_sources = valid_sources;
    this.delegation = prev.delegation;
    this.bundle = prev.bundle;
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
