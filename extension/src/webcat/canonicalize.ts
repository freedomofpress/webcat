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
export function canonicalize(object: object): string {
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
    object.forEach((element) => {
      if (!first) {
        buffer.push(COMMA);
      }
      first = false;
      buffer.push(canonicalize(element));
    });
    buffer.push(RIGHT_SQUARE_BRACKET);
  } else if (typeof object === "object") {
    buffer.push(LEFT_CURLY_BRACKET);
    let first = true;
    Object.keys(object)
      .sort()
      .forEach((property) => {
        if (!first) {
          buffer.push(COMMA);
        }
        first = false;
        buffer.push(canonicalizeString(property));
        buffer.push(COLON);
        // eslint-disable-next-line
        buffer.push(canonicalize((object as any)[property])); // 'any' as a fallback
      });
    buffer.push(RIGHT_CURLY_BRACKET);
  } else {
    throw new TypeError("cannot encode " + object);
  }

  return buffer.join("");
}
