const COMMA = ",";
const COLON = ":";
const LEFT_SQUARE_BRACKET = "[";
const RIGHT_SQUARE_BRACKET = "]";
const LEFT_CURLY_BRACKET = "{";
const RIGHT_CURLY_BRACKET = "}";

function canonicalizeString(string: string): string {
  const escapedString = string.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  return '"' + escapedString + '"';
}

// Keys sort by code point, which is UTF-8 byte order, as the spec and the
// olpc-cjson crate require. Array.prototype.sort() compares UTF-16 code units
// instead, which disagrees for keys above U+FFFF: "\u{10000}" is the pair
// D800 DC00, so .sort() puts it before "\uFFFF", while its UTF-8 bytes
// F0 90 80 80 sort after EF BF BF. Fixed-width hex per code point makes the
// plain string comparison match.
const byCodePoint = (s: string) =>
  Array.from(s, (c) =>
    (c.codePointAt(0) as number).toString(16).padStart(6, "0"),
  ).join("");

// Recursively encodes the supplied value as OLPC canonical JSON, as fixed by
// webcat-spec server.md §1.0: keys sorted by UTF-8 bytes, only `"` and `\`
// escaped, integers only and only in the JS safe range. Archived spec:
// https://web.archive.org/web/20251209150702/http://wiki.laptop.org/go/Canonical_JSON
//
// webcat-infra-chain encodes the same way (via the olpc-cjson crate).
//
// Returns null for anything it can't encode.
export function canonicalize(object: unknown): string | null {
  const buffer: string[] = [];
  if (typeof object === "string") {
    buffer.push(canonicalizeString(object));
  } else if (typeof object === "boolean") {
    buffer.push(JSON.stringify(object));
  } else if (Number.isSafeInteger(object)) {
    buffer.push(JSON.stringify(object));
  } else if (object === null) {
    buffer.push(JSON.stringify(object));
  } else if (Array.isArray(object)) {
    buffer.push(LEFT_SQUARE_BRACKET);
    let first = true;
    for (const element of object) {
      if (!first) {
        buffer.push(COMMA);
      }
      first = false;
      const encoded = canonicalize(element);
      if (encoded === null) return null;
      buffer.push(encoded);
    }
    buffer.push(RIGHT_SQUARE_BRACKET);
  } else if (typeof object === "object") {
    buffer.push(LEFT_CURLY_BRACKET);
    let first = true;
    const keys = Object.keys(object).sort((a, b) =>
      byCodePoint(a) < byCodePoint(b)
        ? -1
        : byCodePoint(a) > byCodePoint(b)
          ? 1
          : 0,
    );
    for (const property of keys) {
      if (!first) {
        buffer.push(COMMA);
      }
      first = false;
      buffer.push(canonicalizeString(property));
      buffer.push(COLON);
      const encoded = canonicalize(
        (object as Record<string, unknown>)[property],
      );
      if (encoded === null) return null;
      buffer.push(encoded);
    }
    buffer.push(RIGHT_CURLY_BRACKET);
  } else {
    return null;
  }

  return buffer.join("");
}
