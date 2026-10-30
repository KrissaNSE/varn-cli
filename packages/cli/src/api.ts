/**
 * Client for the vault read API v1 (docs/features/secure-vault.md, "Read API").
 * Only ciphertext comes back; decryption happens in ./resolve.ts.
 */
import {
  MACHINE_API_ERRORS,
  MACHINE_API_MAX_IDS,
  machineReadResponseSchema,
  type MachineApiError,
  type MachineReadResponse,
} from "../../../src/domain/vault/machine-api";
import { CliError, EXIT, type ExitCode } from "./errors";
import { VERSION } from "./version";

export const DEFAULT_API_URL = "https://www.varnsecurity.se";
export const API_PATH = "/api/vault/v1/collections";
const TIMEOUT_MS = 30_000;
/** Netlify caps a function response at 6 MB; anything far larger is not the vault. */
const MAX_RESPONSE_BYTES = 32 * 1024 * 1024;

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * The API origin from `VARN_API_URL`. HTTPS is required, except for a local
 * development server (localhost, 127.0.0.1, ::1). Only the origin is used.
 */
export function apiOrigin(value: string | undefined): string {
  const text = value?.trim() || DEFAULT_API_URL;
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    throw new CliError(EXIT.config, "VARN_API_URL is not a valid URL.");
  }
  if (url.username || url.password) throw new CliError(EXIT.config, "VARN_API_URL must not contain a user name or password.");
  const local = LOCAL_HOSTS.has(url.hostname) || url.hostname.endsWith(".localhost");
  if (url.protocol === "https:") return url.origin;
  if (url.protocol === "http:" && local) return url.origin;
  throw new CliError(EXIT.config, `VARN_API_URL must use https:// (plain http:// is allowed only for localhost); got ${url.protocol}//${url.host}.`);
}

const ERROR_EXIT: Record<MachineApiError, ExitCode> = {
  invalid_request: EXIT.server,
  unauthorized: EXIT.unauthorized,
  not_entitled: EXIT.notEntitled,
  collection_not_found: EXIT.notFound,
  rate_limited: EXIT.rateLimited,
  vault_disabled: EXIT.vaultDisabled,
  server_error: EXIT.server,
};

const STATUS_ERROR: Record<number, MachineApiError> = {
  400: "invalid_request",
  401: "unauthorized",
  403: "not_entitled",
  404: "collection_not_found",
  429: "rate_limited",
  503: "vault_disabled",
};

function apiError(code: MachineApiError, details: { collectionIds?: string[]; retryAfter?: string | null; status: number }): CliError {
  const messages: Record<MachineApiError, string> = {
    invalid_request: `The API refused the request as malformed (400 invalid_request). This is a bug in varn ${VERSION}; please report it.`,
    unauthorized:
      "The API did not accept the token (401 unauthorized). The machine account may have expired or been revoked, the token may be from another Värn environment, or the call came from outside the account's allowed networks.",
    not_entitled: "The organisation's plan does not include the vault, or its subscription has ended (403 not_entitled).",
    collection_not_found: `This machine account cannot read ${
      details.collectionIds?.length ? `collection ${details.collectionIds.join(", ")}` : "one of the requested collections"
    } (404 collection_not_found). Check the id, or grant the machine access to the collection in Värn.`,
    rate_limited: `Too many requests (429 rate_limited)${details.retryAfter ? `; retry after ${details.retryAfter} seconds` : ""}. The limit is 60 requests a minute per machine account and per IP address.`,
    vault_disabled: "The vault is switched off on this Värn server (503 vault_disabled).",
    server_error: `The API failed (${details.status} server_error). Try again later.`,
  };
  return new CliError(ERROR_EXIT[code], messages[code]);
}

export interface FetchCollectionsOptions {
  origin: string;
  bearer: string;
  /** Collection ids to fetch; undefined fetches every collection the machine holds. */
  ids?: string[];
  fetch?: typeof globalThis.fetch;
}

async function readBody(response: Response): Promise<string> {
  const length = Number(response.headers.get("content-length") ?? "0");
  if (length > MAX_RESPONSE_BYTES) throw new CliError(EXIT.network, "The API response is too large.");
  const text = await response.text();
  if (text.length > MAX_RESPONSE_BYTES) throw new CliError(EXIT.network, "The API response is too large.");
  return text;
}

async function request(opts: FetchCollectionsOptions, ids: string[] | undefined): Promise<MachineReadResponse> {
  const url = new URL(API_PATH, opts.origin);
  if (ids) url.searchParams.set("ids", ids.join(","));
  const doFetch = opts.fetch ?? globalThis.fetch;
  let response: Response;
  try {
    response = await doFetch(url, {
      method: "GET",
      headers: { authorization: `Bearer ${opts.bearer}`, accept: "application/json", "user-agent": `varn-cli/${VERSION}` },
      // Never follow a redirect with the bearer value: report it instead.
      redirect: "manual",
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch (error) {
    const timeout = error instanceof Error && (error.name === "TimeoutError" || error.name === "AbortError");
    const cause = error instanceof Error && error.cause instanceof Error ? (error.cause as NodeJS.ErrnoException).code ?? error.cause.message : undefined;
    throw new CliError(
      EXIT.network,
      timeout ? `The API at ${opts.origin} did not answer within ${TIMEOUT_MS / 1000} seconds.` : `Could not reach the API at ${opts.origin}${cause ? ` (${cause})` : ""}.`,
    );
  }

  if (response.status >= 300 && response.status < 400) {
    const location = response.headers.get("location");
    let where = "";
    try {
      if (location) where = ` to ${new URL(location, url).origin}`;
    } catch {
      // ignore an unparsable location
    }
    throw new CliError(EXIT.network, `The API answered with a redirect${where}. varn does not follow redirects; set VARN_API_URL to the right address.`);
  }

  const text = await readBody(response);
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    json = undefined;
  }

  if (response.status === 200) {
    const parsed = machineReadResponseSchema.safeParse(json);
    if (!parsed.success) {
      throw new CliError(EXIT.network, "The API response is not a Värn vault API v1 response. Check VARN_API_URL, or update varn.");
    }
    return parsed.data;
  }

  const body = (json && typeof json === "object" ? json : {}) as { error?: unknown; collection_ids?: unknown };
  const code: MachineApiError | undefined =
    typeof body.error === "string" && (MACHINE_API_ERRORS as readonly string[]).includes(body.error)
      ? (body.error as MachineApiError)
      : STATUS_ERROR[response.status];
  const collectionIds = Array.isArray(body.collection_ids) ? body.collection_ids.filter((id): id is string => typeof id === "string" && /^[0-9a-f-]{36}$/i.test(id)) : undefined;
  throw apiError(code ?? "server_error", { collectionIds, retryAfter: response.headers.get("retry-after"), status: response.status });
}

/**
 * Fetches collections the machine may read. With ids, at most 100 per request
 * (the API's limit), so a larger list is fetched in several requests.
 */
export async function fetchCollections(opts: FetchCollectionsOptions): Promise<MachineReadResponse> {
  if (!opts.ids) return request(opts, undefined);
  const unique = [...new Set(opts.ids)];
  let merged: MachineReadResponse | undefined;
  for (let i = 0; i < unique.length; i += MACHINE_API_MAX_IDS) {
    const page = await request(opts, unique.slice(i, i + MACHINE_API_MAX_IDS));
    if (!merged) merged = page;
    else merged = { ...merged, collections: [...merged.collections, ...page.collections] };
  }
  if (!merged) throw new CliError(EXIT.internal, "No collections requested.");
  return merged;
}
