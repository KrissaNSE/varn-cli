/**
 * Secret references (design doc §2):
 *
 *   varn://<org-slug>/<collection>/<item>/<field>
 *
 * `<collection>` and `<item>` are names (case-insensitive, URL-encoded) or ids
 * written `id:<uuid>`. Whether a segment is an id is decided before decoding,
 * so an item really named "id:…" can still be referenced as `id%3A…`.
 * `<field>` is password, username, url or notes. Names are resolved on the
 * machine (./resolve.ts): the server never sees them.
 */
import { CliError, EXIT } from "./errors";

export const REFERENCE_PREFIX = "varn://";
export const FIELDS = ["password", "username", "url", "notes"] as const;
export type Field = (typeof FIELDS)[number];

export type Selector = { kind: "id"; id: string } | { kind: "name"; name: string };

export interface SecretReference {
  /** The reference exactly as written. */
  raw: string;
  org: string;
  collection: Selector;
  item: Selector;
  field: Field;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isReference(value: string): boolean {
  return value.startsWith(REFERENCE_PREFIX);
}

function invalid(raw: string, why: string): CliError {
  return new CliError(EXIT.badReference, `Invalid reference ${JSON.stringify(raw)}: ${why}.`);
}

function decode(raw: string, segment: string, what: string): string {
  let decoded: string;
  try {
    decoded = decodeURIComponent(segment);
  } catch {
    throw invalid(raw, `the ${what} is not valid URL encoding`);
  }
  if (decoded.length === 0) throw invalid(raw, `the ${what} is empty`);
  return decoded;
}

function selector(raw: string, segment: string, what: string): Selector {
  if (/^id:/i.test(segment)) {
    const id = segment.slice(3);
    if (!UUID.test(id)) throw invalid(raw, `the ${what} id is not a UUID`);
    return { kind: "id", id: id.toLowerCase() };
  }
  return { kind: "name", name: decode(raw, segment, `${what} name`) };
}

/** Comparison form of a name: Unicode NFC and lower case, so "Produktion", "produktion" and "PRODUKTION" match. */
export function nameKey(name: string): string {
  return name.normalize("NFC").toLowerCase();
}

export function parseReference(raw: string): SecretReference {
  if (!isReference(raw)) throw invalid(raw, `it must start with ${REFERENCE_PREFIX}`);
  const rest = raw.slice(REFERENCE_PREFIX.length);
  if (/\s/.test(rest)) throw invalid(raw, "it contains whitespace (write a space in a name as %20)");
  if (/[?#]/.test(rest)) throw invalid(raw, "it contains ? or # (URL-encode them in names as %3F and %23)");
  const segments = rest.split("/");
  if (segments.length !== 4) throw invalid(raw, "expected varn://<organisation>/<collection>/<item>/<field>");
  const [orgSegment, collectionSegment, itemSegment, fieldSegment] = segments as [string, string, string, string];
  if (orgSegment.length === 0) throw invalid(raw, "the organisation is empty");
  if (collectionSegment.length === 0) throw invalid(raw, "the collection is empty");
  if (itemSegment.length === 0) throw invalid(raw, "the item is empty");
  const field = decode(raw, fieldSegment, "field").toLowerCase();
  if (!(FIELDS as readonly string[]).includes(field)) throw invalid(raw, `the field must be one of ${FIELDS.join(", ")}`);
  return {
    raw,
    org: decode(raw, orgSegment, "organisation").toLowerCase(),
    collection: selector(raw, collectionSegment, "collection"),
    item: selector(raw, itemSegment, "item"),
    field: field as Field,
  };
}

/**
 * Placeholders in a template for `varn inject`: `{{ varn://… }}`, with optional
 * spaces inside the braces. Everything up to the closing braces is taken as
 * the reference, so a name with a raw space is reported rather than skipped.
 */
export const PLACEHOLDER = /\{\{\s*(varn:\/\/[^{}]*?)\s*\}\}/g;
