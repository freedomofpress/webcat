import {
  canonicalizeJCS,
  canonicalizeOLPC,
} from "@freedomofpress/crypto-browser";

// Spec server.md §1.0: a manifest with manifest_schema is signed over RFC 8785,
// one without it over OLPC canonical JSON.
export const hasSchema = (doc: object): boolean => "manifest_schema" in doc;

// Throws when the dialect cannot encode the document.
export function canonicalForm(doc: object): string {
  return (hasSchema(doc) ? canonicalizeJCS : canonicalizeOLPC)(doc);
}
