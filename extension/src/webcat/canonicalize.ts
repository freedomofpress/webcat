// From https://github.com/theupdateframework/tuf-js/blob/38d537ea883e8bb38ee6ab17b5f59ee479d0eab2/packages/canonical-json/lib/index.js

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

// Recursively encodes the supplied object according to the canonical JSON form
// as specified at http://wiki.laptop.org/go/Canonical_JSON. It's a restricted
// dialect of JSON in which keys are lexically sorted, floats are not allowed,
// and only double quotes and backslashes are escaped.
/**
 * JCS-canonicalizes a value. Returns null if it contains a value that cannot
 * be encoded (e.g. a non-integer number).
 */
export function canonicalize(object: unknown): string | null {
  const buffer: string[] = [];
  if (typeof object === "string") {
    buffer.push(canonicalizeString(object));
  } else if (typeof object === "boolean") {
    buffer.push(JSON.stringify(object));
  } else if (Number.isInteger(object)) {
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
    for (const property of Object.keys(object).sort()) {
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
