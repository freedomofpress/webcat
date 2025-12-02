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
import { Base64KeyHash, CosignedTreeHead, KeyHash } from "@freedomofpress/sigsum/dist/types";

import { getFQDNEnrollment } from "./db";
import { WebcatError, WebcatErrorCode } from "./interfaces/errors";
import { parseContentSecurityPolicy } from "./parsers";
import { getFQDNSafe } from "./utils";

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

      if ((await getFQDNEnrollment(fqdn)).length !== 0) {
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
  const trimmed = value.trim();

  // Reject protocol-relative URLs: "//example.com"
  if (trimmed.startsWith("//")) return false;

  // Reject ANY absolute URL with a scheme: "https:", "javascript:", "data:", etc.
  const SCHEME_RE = /^[a-zA-Z][a-zA-Z0-9+.-]*:/;
  if (SCHEME_RE.test(trimmed)) return false;

  return true;
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
