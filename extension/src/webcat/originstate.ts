import { bundle_name, bundle_prev_name } from "../config";
import { canonicalize } from "./canonicalize";
import { stringToUint8Array } from "./encoding";
import {
  Bundle,
  Enrollment,
  EnrollmentTypes,
  Manifest,
  SigstoreSignatures,
  SigsumSignatures,
} from "./interfaces/bundle";
import { Database } from "./interfaces/database";
import { WebcatError, WebcatErrorCode } from "./interfaces/errors";
import {
  CachePartition,
  OriginState as IOriginState,
  OriginStateFailed,
  OriginStateVerifiedEnrollment,
  OriginStateVerifiedManifest,
} from "./interfaces/originstate";
import { arraysEqual } from "./utils";
import { SHA256 } from "./utils";
import { validateCSP, validateSigstoreEnrollment } from "./validators";
import {
  validateManifest,
  validateSigsumEnrollment,
  verifySigstoreManifest,
  verifySigsumManifest,
} from "./validators";

type BundleFetch = {
  promise: Promise<Response>;
  error?: WebcatError;
  value?: Bundle;
};

export class BundleFetcher {
  readonly current: BundleFetch;
  readonly previous: BundleFetch;

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

  async awaitAll(): Promise<void> {
    for (const slot of [this.current, this.previous]) {
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

// The OriginState class caches origins and assumes safe defaults. We assume we are enrolled and nothing is verified.
export class OriginState implements IOriginState {
  status:
    | "request_sent"
    | "verified_enrollment"
    | "verified_manifest"
    | "failed";

  readonly #db: Database;
  readonly #cachePartition: CachePartition;
  readonly enrollment_hash: Uint8Array;

  #bundle?: Bundle;
  fetcher: BundleFetcher;
  enrollment?: Enrollment;
  manifest?: Manifest;
  delegation?: string;
  error?: WebcatError;

  stale = false;

  // Due to list logic, we support only one app per domain, and that should be a privileged one
  // But that is enforced in request.ts
  constructor(
    db: Database,
    fetcher: BundleFetcher,
    enrollment_hash: Uint8Array,
    cachePartition: CachePartition,
    delegation?: string,
  ) {
    this.#db = db;
    this.fetcher = fetcher;
    this.enrollment_hash = enrollment_hash;
    this.#cachePartition = cachePartition;
    this.delegation = delegation;
    this.status = "request_sent";
  }

  isRequestSent(): boolean {
    return (
      this.status === "request_sent" &&
      this.enrollment === undefined &&
      this.manifest === undefined &&
      this.error === undefined
    );
  }

  #fail(error: WebcatError) {
    this.status = "failed";
    this.error = error;
  }

  isFailed(): this is OriginStateFailed {
    return this.status === "failed";
  }

  #setVerifiedEnrollment(enrollment: Enrollment, delegation?: string) {
    this.status = "verified_enrollment";
    this.enrollment = enrollment;
    this.delegation = delegation;
  }

  isEnrollmentVerified(): this is OriginStateVerifiedEnrollment {
    return (
      this.status === "verified_enrollment" && this.enrollment !== undefined
    );
  }

  #setVerifiedManifest(manifest: Manifest) {
    this.status = "verified_manifest";
    this.manifest = manifest;
  }

  isManifestVerified(): this is OriginStateVerifiedManifest {
    return this.status === "verified_manifest" && this.manifest !== undefined;
  }

  async #verifyDelegation(delegation: string): Promise<boolean> {
    const delegation_hash = await this.#db.getFQDNEnrollment(
      delegation,
      this.#cachePartition,
    );
    return (
      delegation_hash && arraysEqual(delegation_hash, this.enrollment_hash)
    );
  }

  // This functiont ries to verify the enrollment information against the value in the local list
  // It will also return errors while fetching the bundles (though they are generated in awaitBundles)
  // and tell the next stages whether they should use the current or the previous bundle
  async verifyEnrollment(enrollment?: Enrollment, delegation?: string) {
    let verified_delegation;
    if (delegation && (await this.#verifyDelegation(delegation))) {
      verified_delegation = delegation;
    }

    // Enrollment info can be fetched from a manifest bundle,
    // or we should support supplying it differently, such is in http headers
    if (!enrollment) {
      if (!this.fetcher.current.value) {
        if (!this.fetcher.current.error) {
          throw new Error("verifyEnrollment called before fetcher is ready");
        }
        return this.#fail(this.fetcher.current.error);
      }
      enrollment = this.fetcher.current.value.enrollment;
    }

    const canonicalized = stringToUint8Array(canonicalize(enrollment));
    const canonicalized_hash = new Uint8Array(await SHA256(canonicalized));

    // If it doesn't match, stop early
    const match = arraysEqual(this.enrollment_hash, canonicalized_hash);
    // In this case, we already tried both bundles and we should bail
    // Or we got direct enrollment passed, and we shpuldn't fallback automatically
    if (match) {
      this.#bundle = this.fetcher.current.value;
    } else {
      // If we are here, and the previous fetch failed, we fail on MISMATCH
      // because it means the main enrollment MISMATCHED and there's no fallback
      if (!this.fetcher.previous.value) {
        return this.#fail(new WebcatError(WebcatErrorCode.Enrollment.MISMATCH));
      }
      enrollment = this.fetcher.previous.value.enrollment;

      const canonicalized_prev = stringToUint8Array(canonicalize(enrollment));
      const canonicalized_hash_prev = new Uint8Array(
        await SHA256(canonicalized_prev),
      );

      // If this also fails it's fatal
      if (!arraysEqual(this.enrollment_hash, canonicalized_hash_prev)) {
        return this.#fail(new WebcatError(WebcatErrorCode.Enrollment.MISMATCH));
      }
      this.#bundle = this.fetcher.previous.value;
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
      return this.#fail(err);
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
    return this.#setVerifiedEnrollment(enrollment, verified_delegation);
  }

  async verifyManifest(
    manifest?: Manifest,
    signatures?: SigsumSignatures | SigstoreSignatures,
  ) {
    if (!this.isEnrollmentVerified()) {
      throw new Error("verifyManifest called before verifyEnrollment");
    }
    // Manifest info can be fetched from a manifest bundle,
    // or we should support supplying it differently
    // If enrollment information is passed from headers or another source, then we do not support
    // a fallback bundle at the moment
    if (!manifest || !signatures) {
      // awaitBundle checks already that manifest exists
      // eslint-disable-next-line
      manifest = this.#bundle!.manifest;
      // eslint-disable-next-line
      signatures = this.#bundle!.signatures;
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
      return this.#fail(verify_error);
    }

    const format_error = validateManifest(manifest);
    if (format_error) {
      return this.#fail(format_error);
    }

    // ValidateCSP will populate this based on hosts presents in both
    // the CSP policies specified AND the enrollment list
    // If an enrolled CSP policy has non-enrolled hosts, then it will throw
    const valid_sources: Set<string> = new Set();

    // Validate the default CSP
    try {
      await validateCSP(
        this.#db,
        manifest.default_csp,
        valid_sources,
        this.#cachePartition,
      );
    } catch (e) {
      //return new OriginStateFailed(this, `failed parsing default_csp: ${e}`);
      return this.#fail(
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
          await validateCSP(this.#db, csp, valid_sources, this.#cachePartition);
        } catch (e) {
          return this.#fail(
            new WebcatError(WebcatErrorCode.Manifest.EXTRA_CSP_INVALID, [
              String(e),
            ]),
          );
        }
      } else {
        return this.#fail(
          new WebcatError(WebcatErrorCode.Manifest.EXTRA_CSP_MALFORMED, [
            String(path),
          ]),
        );
      }
    }
    return this.#setVerifiedManifest(manifest);
  }

  verifyCSP(csp: string, pathname: string) {
    if (!this.isManifestVerified()) {
      throw new Error("verifyCSP called before verifyManifest");
    }
    // Consider only the first CSP. See
    // https://github.com/freedomofpress/webcat/issues/160
    csp = csp.split(",")[0];

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
