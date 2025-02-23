import { getFQDNPolicy } from "./db";
import { parseContentSecurityPolicy } from "./parsers";
import { getFQDNSafe } from "./utils";

export async function validateCSP(
  csp: string,
  valid_sources: Set<string>,
) {
  // See https://github.com/freedomofpress/webcat/issues/9
  // https://github.com/freedomofpress/webcat/issues/3

  enum directives {
    DefaultSrc = "default-src",
    ScriptSrc = "script-src",
    StyleSrc = "style-src",
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

  // Setp 1: check default src, which is the default for almost everything.
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

      if ((await getFQDNPolicy(fqdn)).length !== 0) {
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

  // Step 3: think about scripts
  const script_src = parsedCSP.get(directives.ScriptSrc);
  if (default_src_is_none == false && (!script_src || script_src.length < 1)) {
    throw new Error(
      `${directives.DefaultSrc} is not none, and ${directives.ScriptSrc} is not defined.`,
    );
  } else if (script_src) {
    for (const src of script_src) {
      await isSourceAllowed(
        src,
        directives.ScriptSrc,
        [
          source_keywords.None,
          source_keywords.Self,
          source_keywords.WasmUnsafeEval,
        ],
        // Here allowing hash would break the WASM hooking; as we are no longer injecting
        // Via a content_script, but rather at the network level on script files, having embedded
        // JS in HTML page could break the assumptions.
        [],
      );
    }
  }

  // Step 4: validate style-src
  const style_src = parsedCSP.get(directives.StyleSrc);
  if (default_src_is_none == false && (!style_src || style_src.length < 1)) {
    throw new Error(
      `${directives.DefaultSrc} is not none, and ${directives.StyleSrc} is not defined.`,
    );
  } else if (style_src) {
    for (const src of style_src) {
      await isSourceAllowed(
        src,
        directives.StyleSrc,
        [
          source_keywords.None,
          source_keywords.Self,
          // TODO eventually the following 2 should disappear from here
          source_keywords.UnsafeInline,
          source_keywords.UnsafeHashes,
        ],
        // We could allow remote verified origins, but I'd lean towards not
        [source_types.Hash],
      );
    }
  }

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
