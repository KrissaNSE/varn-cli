/**
 * Contract of the vault read API for machine accounts, version 1:
 *
 *   GET https://www.varnsecurity.se/api/vault/v1/collections[?ids=<uuid>,<uuid>,…]
 *   Authorization: Bearer <base64url(auth_secret)>      (see machineBearer in ./crypto)
 *
 * The response carries only ciphertext, wrapped keys, public keys, ids,
 * versions and timestamps: the machine decrypts locally with the private key in
 * its token (docs/features/secure-vault.md, "Read API"). This module is pure so
 * the `varn` CLI can bundle it next to ./crypto; the route handler validates
 * what it sends with the same schema. Fields are only ever added within v1;
 * anything that changes or removes one is v2 (a new path).
 */
import { z } from "zod";

export const MACHINE_API_VERSION = 1;
/** At most this many collection ids per request. */
export const MACHINE_API_MAX_IDS = 100;

const b64 = z.string().regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/);
const publicKey = z.string().regex(/^[A-Za-z0-9+/]{87}=$/);
const iv = z.string().regex(/^[A-Za-z0-9+/]{16}$/);
const version = z.number().int().min(1);
const timestamp = z.string().min(1);

/** A collection key wrapped for this machine (threat model §5.3, purpose "machine-grant"). */
export const machineGrantSchema = z.object({
  key_version: version,
  ephemeral_public_key: publicKey,
  iv,
  wrapped_key: z.string().regex(/^[A-Za-z0-9+/]{64}$/),
  /** The member who wrapped it; part of the HKDF info and AAD. */
  sender_user_id: z.uuid(),
  sender_public_key: publicKey,
});

/** An item: AAD "varn-vault/v1/item|org|collection|id|version|key_version". */
export const machineItemSchema = z.object({
  id: z.uuid(),
  version,
  key_version: version,
  iv,
  ciphertext: b64,
  /** v1 never serves file contents; the item's plaintext still names the file. */
  has_file: z.boolean(),
  created_at: timestamp,
  updated_at: timestamp,
});

export const machineCollectionSchema = z.object({
  id: z.uuid(),
  /** The collection's current key version. */
  key_version: version,
  /** Encrypted name: AAD "varn-vault/v1/collection-name|org|collection|name.version|key_version". */
  name: z.object({ version, iv, ciphertext: b64 }),
  /** Every grant this machine has for the collection: the current key version, plus older ones during a rotation. */
  grants: z.array(machineGrantSchema),
  items: z.array(machineItemSchema),
});

export const machineReadResponseSchema = z.object({
  api_version: z.literal(MACHINE_API_VERSION),
  organization: z.object({ id: z.uuid(), slug: z.string().min(1) }),
  machine: z.object({ id: z.uuid(), public_key: publicKey, expires_at: timestamp }),
  collections: z.array(machineCollectionSchema),
});

export type MachineGrant = z.infer<typeof machineGrantSchema>;
export type MachineItem = z.infer<typeof machineItemSchema>;
export type MachineCollection = z.infer<typeof machineCollectionSchema>;
export type MachineReadResponse = z.infer<typeof machineReadResponseSchema>;

/**
 * Error codes, with their HTTP status:
 *   400 invalid_request         malformed `ids`
 *   401 unauthorized            missing, malformed, unknown, expired or revoked token, or a call from outside
 *                               the machine's allowed networks (always the same response)
 *   403 not_entitled            the organisation's plan does not include the vault (or its subscription has ended)
 *   404 collection_not_found    a requested id is not a collection this machine may read; `collection_ids` lists them
 *   429 rate_limited            too many requests for this machine (60 a minute) or from this IP (edge limit)
 *   503 vault_disabled          the vault is switched off on the platform
 *   500 server_error
 */
export const MACHINE_API_ERRORS = [
  "invalid_request",
  "unauthorized",
  "not_entitled",
  "collection_not_found",
  "rate_limited",
  "vault_disabled",
  "server_error",
] as const;
export type MachineApiError = (typeof MACHINE_API_ERRORS)[number];

export interface MachineErrorResponse {
  api_version: typeof MACHINE_API_VERSION;
  error: MachineApiError;
  collection_ids?: string[];
}

export const MACHINE_API_STATUS: Record<MachineApiError, number> = {
  invalid_request: 400,
  unauthorized: 401,
  not_entitled: 403,
  collection_not_found: 404,
  rate_limited: 429,
  vault_disabled: 503,
  server_error: 500,
};
