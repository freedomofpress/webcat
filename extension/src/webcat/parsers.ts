import { Issuers,Signer } from "./interfaces";

export function parseSigners(signers: string): Set<Signer> {
  const outputSigners: Set<Signer> = new Set();
  let parsedHeader = {};
  try {
    parsedHeader = JSON.parse(signers);
  } catch (error) {
    throw new Error(`Error parsing JSON in x-sigstore-signers ${error}`);
  }

  if (!Array.isArray(parsedHeader)) {
    throw new Error(
      "Header x-sigstore-signers does not JSON decode to an array.",
    );
  }

  for (const signer of parsedHeader) {
    if (
      typeof signer.identity !== "string" ||
      typeof signer.issuer !== "string"
    ) {
      throw new Error(
        "Found invalid tuple of [issuer, identity] when parsing x-sigstore-signers.",
      );
    }

    if (!Object.values(Issuers).includes(signer.issuer as Issuers)) {
      throw new Error(`${signer.issuer} is not a valid OIDC issuer.`);
    }

    if (signer.identity.length < 3 || signer.identity.length > 255) {
      throw new Error(`${signer.identity} is not a valid OIDC identity.`);
    }

    outputSigners.add([signer.issuer, signer.identity.toLowerCase()]);
  }

  // Sort in a set for consistency
  const sortedSigners = Array.from(outputSigners).sort(
    ([issuerA, identityA], [issuerB, identityB]) =>
      identityA.localeCompare(identityB) || issuerA.localeCompare(issuerB),
  );

  // Recreate the Set with normalized (sorted) order
  return new Set(sortedSigners);
}

export function parseThreshold(
  threshold: string,
  signersLength: number,
): number {
  const outputThreshold = Number(threshold);
  if (outputThreshold < 1) {
    throw new Error("Signing threshold is less than 1.");
  }
  if (outputThreshold > signersLength) {
    throw new Error(
      "Signing threshold is greater than the number of possible signers.",
    );
  }

  return outputThreshold;
}

// From https://github.com/helmetjs/content-security-policy-parser/blob/main/mod.ts

type ParsedContentSecurityPolicy = Map<string, string[]>;

// "ASCII whitespace is U+0009 TAB, U+000A LF, U+000C FF, U+000D CR, or
// U+0020 SPACE."
//
// See <https://infra.spec.whatwg.org/#ascii-whitespace>.
const ASCII_WHITESPACE_CHARS = "\t\n\f\r ";
const ASCII_WHITESPACE = RegExp(`[${ASCII_WHITESPACE_CHARS}]+`);
const ASCII_WHITESPACE_AT_START = RegExp(`^[${ASCII_WHITESPACE_CHARS}]+`);
const ASCII_WHITESPACE_AT_END = RegExp(`[${ASCII_WHITESPACE_CHARS}]+$`);

// "An ASCII code point is a code point in the range U+0000 NULL to
// U+007F DELETE, inclusive." See <https://infra.spec.whatwg.org/#ascii-string>.
// deno-lint-ignore no-control-regex
const ASCII = /^[\x00-\x7f]*$/;

/**
 * Parse a serialized Content Security Policy via [the spec][0].
 *
 * [0]: https://w3c.github.io/webappsec-csp/#parse-serialized-policy
 *
 * @param policy The serialized Content Security Policy to parse.
 * @returns A Map of Content Security Policy directives.
 * @example
 * parseContentSecurityPolicy(
 *   "default-src 'self'; script-src 'unsafe-eval' scripts.example; object-src; style-src styles.example",
 * );
 * // => Map(4) {
 * //      "default-src" => ["'self'"],
 * //      "script-src" => ["'unsafe-eval'", "scripts.example"],
 * //      "object-src" => [],
 * //      "style-src" => ["styles.example"],
 * //    }
 */
export function parseContentSecurityPolicy(
  policy: string,
): ParsedContentSecurityPolicy {
  const result: ParsedContentSecurityPolicy = new Map();

  // "For each token returned by strictly splitting serialized on the
  // U+003B SEMICOLON character (;):"
  for (let token of policy.split(";")) {
    // "1. Strip leading and trailing ASCII whitespace from token."
    token = token
      .replace(ASCII_WHITESPACE_AT_START, "")
      .replace(ASCII_WHITESPACE_AT_END, "");

    // "2. If token is an empty string, or if token is not an ASCII string,
    //     continue."
    if (!token || !ASCII.test(token)) continue;

    // We do these at the same time:
    // "3. Let directive name be the result of collecting a sequence of
    //     code points from token which are not ASCII whitespace."
    // "6. Let directive value be the result of splitting token on
    //     ASCII whitespace."
    const [rawDirectiveName, ...directiveValue] = token.split(ASCII_WHITESPACE);

    // "4. Set directive name to be the result of running ASCII lowercase on
    //     directive name."
    const directiveName = rawDirectiveName!.toLowerCase();

    // "5. If policy's directive set contains a directive whose name is
    //     directive name, continue."
    if (result.has(directiveName)) continue;

    // "7. Let directive be a new directive whose name is directive name, and
    //     value is directive value."
    // "8. Append directive to policy's directive set."
    result.set(directiveName, directiveValue);
  }

  return result;
}
