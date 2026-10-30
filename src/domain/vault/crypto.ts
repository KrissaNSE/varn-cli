/**
 * Värn Vault cryptography (format v1). Runs in the browser, and in Node for
 * tests, using only the Web Crypto API. Nothing here talks to the network,
 * logs, or persists anything: callers get ciphertext and wrapped keys back and
 * decide where they go. The design and its threat model are in
 * docs/VAULT-THREAT-MODEL.md (§5); keep the two in sync.
 *
 * Summary
 *   passphrase --PBKDF2-SHA-256 (>= 600 000)--> KEK --AES-GCM--> identity private key (ECDH P-256)
 *   sender/recipient ECDH + ephemeral ECDH --HKDF-SHA-256--> KWK --AES-GCM--> collection key (AES-256-GCM)
 *   collection key --AES-256-GCM, AAD = org|collection|item|version|key version--> item / file
 *   collection key --AES-256-GCM, AAD = org|collection|version|key version--> collection name
 *   optional recovery code (printed) = recovery private key --ECDH/HKDF--> KWK --> every collection key
 *   machine token = machine private key (d) --ECDH/HKDF--> KWK --> the collections granted to that machine;
 *                   d --HKDF--> auth_secret (bearer for the read API), stored only as SHA-256(auth_secret)
 *
 * An organisation's vault holds one or more collections; each has its own
 * versioned key and its own grants (threat model §5.3). Every grant, item,
 * file, name and recovery attestation binds the collection id, so ciphertext
 * cannot be moved between collections without the target collection's key.
 *
 * Rules
 *   - Never log, throw or return a passphrase, raw key or plaintext in an error.
 *   - Unlocked identity private keys are non-extractable. Collection keys are
 *     only extractable when the caller asks (admins need that to grant and rotate).
 *   - Every AAD / HKDF info string starts with "varn-vault/v1/<purpose>" and is
 *     built from validated UUIDs and integers only, so it is unambiguous.
 */
import {
  COLLECTION_NAME_PADDING_BYTES,
  FILE_PADDING_BYTES,
  ITEM_PADDING_BYTES,
  VAULT_LIMITS,
  collectionNamePayloadSchema,
  vaultItemPayloadSchema,
  type VaultFileMeta,
  type VaultItemPayload,
} from "./model";

export const PBKDF2_ITERATIONS = 600_000;
export const PBKDF2_MAX_ITERATIONS = 10_000_000;
const SALT_BYTES = 16;
const IV_BYTES = 12;
const P256_RAW_PUBLIC_BYTES = 65;

export type VaultCryptoErrorCode =
  | "wrong_passphrase"
  | "decrypt_failed"
  | "grant_invalid"
  | "invalid_input"
  | "too_large"
  | "weak_kdf"
  | "integrity"
  | "recovery_code_invalid"
  | "machine_token_invalid";

/** Carries only a code: messages never contain secrets. */
export class VaultCryptoError extends Error {
  constructor(public readonly code: VaultCryptoErrorCode) {
    super(`vault_crypto:${code}`);
    this.name = "VaultCryptoError";
  }
}

type Bytes = Uint8Array<ArrayBuffer>;

function subtle(): SubtleCrypto {
  const c = globalThis.crypto;
  if (!c?.subtle) throw new VaultCryptoError("invalid_input");
  return c.subtle;
}

function randomBytes(n: number): Bytes {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

const encoder = new TextEncoder();
const utf8 = (s: string): Bytes => {
  const encoded = encoder.encode(s);
  const out = new Uint8Array(encoded.length);
  out.set(encoded);
  return out;
};

function concat(...parts: Uint8Array[]): Bytes {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

export function toBase64(bytes: Uint8Array | ArrayBuffer): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < view.length; i += CHUNK) {
    binary += String.fromCharCode(...view.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export function fromBase64(value: string): Bytes {
  if (typeof value !== "string" || !BASE64.test(value)) throw new VaultCryptoError("invalid_input");
  const binary = atob(value);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(value: string): Bytes {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]*$/.test(value)) throw new VaultCryptoError("invalid_input");
  const b64 = value.replace(/-/g, "+").replace(/_/g, "/");
  return fromBase64(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
}

async function sha256(bytes: Bytes): Promise<Bytes> {
  return new Uint8Array(await subtle().digest("SHA-256", bytes));
}

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  return [...(await sha256(copy))].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ---------------------------------------------------------------------------
// Context validation (keeps AAD strings unambiguous)
// ---------------------------------------------------------------------------

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function uuid(value: string): string {
  if (typeof value !== "string" || !UUID.test(value)) throw new VaultCryptoError("invalid_input");
  return value;
}

function positiveInt(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1) throw new VaultCryptoError("invalid_input");
  return value;
}

const aad = (purpose: string, ...parts: (string | number)[]) => utf8([`varn-vault/v1/${purpose}`, ...parts].join("|"));

// ---------------------------------------------------------------------------
// Identity key pair (ECDH P-256), protected by the vault passphrase
// ---------------------------------------------------------------------------

export interface IdentityContext {
  orgId: string;
  userId: string;
}

/** What the server stores for a member's key pair (all base64 except iterations). */
export interface IdentityRecord {
  publicKey: string;
  wrappedPrivateKey: string;
  iv: string;
  salt: string;
  iterations: number;
}

export interface UnlockedIdentity extends IdentityContext {
  publicKey: CryptoKey;
  publicKeyB64: string;
  /** Non-extractable; usable only for ECDH deriveBits. */
  privateKey: CryptoKey;
}

const ECDH_P256 = { name: "ECDH", namedCurve: "P-256" } as const;

async function deriveKek(passphrase: string, salt: Bytes, iterations: number): Promise<CryptoKey> {
  if (!Number.isSafeInteger(iterations) || iterations < PBKDF2_ITERATIONS || iterations > PBKDF2_MAX_ITERATIONS) {
    throw new VaultCryptoError("weak_kdf");
  }
  if (typeof passphrase !== "string" || passphrase.length === 0) throw new VaultCryptoError("invalid_input");
  const base = await subtle().importKey("raw", utf8(passphrase.normalize("NFKC")), "PBKDF2", false, ["deriveKey"]);
  return subtle().deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["wrapKey", "unwrapKey"],
  );
}

const identityAad = (ctx: IdentityContext, publicKeyB64: string, iterations: number) =>
  aad("identity", uuid(ctx.orgId), uuid(ctx.userId), publicKeyB64, iterations);

export async function importPublicKey(publicKeyB64: string): Promise<CryptoKey> {
  const raw = fromBase64(publicKeyB64);
  if (raw.length !== P256_RAW_PUBLIC_BYTES || raw[0] !== 0x04) throw new VaultCryptoError("invalid_input");
  try {
    return await subtle().importKey("raw", raw, ECDH_P256, true, []);
  } catch {
    throw new VaultCryptoError("invalid_input");
  }
}

async function wrapIdentity(ctx: IdentityContext, privateKey: CryptoKey, publicKeyB64: string, passphrase: string) {
  const salt = randomBytes(SALT_BYTES);
  const iv = randomBytes(IV_BYTES);
  const kek = await deriveKek(passphrase, salt, PBKDF2_ITERATIONS);
  const wrapped = await subtle().wrapKey("pkcs8", privateKey, kek, {
    name: "AES-GCM",
    iv,
    additionalData: identityAad(ctx, publicKeyB64, PBKDF2_ITERATIONS),
  });
  const record: IdentityRecord = {
    publicKey: publicKeyB64,
    wrappedPrivateKey: toBase64(wrapped),
    iv: toBase64(iv),
    salt: toBase64(salt),
    iterations: PBKDF2_ITERATIONS,
  };
  return { record, kek };
}

async function unwrapIdentityKey(
  ctx: IdentityContext,
  record: IdentityRecord,
  kek: CryptoKey,
  extractable: boolean,
): Promise<CryptoKey> {
  try {
    return await subtle().unwrapKey(
      "pkcs8",
      fromBase64(record.wrappedPrivateKey),
      kek,
      { name: "AES-GCM", iv: fromBase64(record.iv), additionalData: identityAad(ctx, record.publicKey, record.iterations) },
      ECDH_P256,
      extractable,
      ["deriveBits"],
    );
  } catch (error) {
    if (error instanceof VaultCryptoError) throw error;
    throw new VaultCryptoError("wrong_passphrase");
  }
}

/** Creates a member's key pair for one organisation and wraps it under the passphrase. */
export async function createIdentity(
  ctx: IdentityContext,
  passphrase: string,
): Promise<{ record: IdentityRecord; identity: UnlockedIdentity }> {
  const pair = (await subtle().generateKey(ECDH_P256, true, ["deriveBits"])) as CryptoKeyPair;
  const publicKeyB64 = toBase64(await subtle().exportKey("raw", pair.publicKey));
  const { record, kek } = await wrapIdentity(ctx, pair.privateKey, publicKeyB64, passphrase);
  // Re-import from the wrapped form: proves the record opens, and leaves only a non-extractable key in memory.
  const privateKey = await unwrapIdentityKey(ctx, record, kek, false);
  return { record, identity: { ...ctx, publicKey: pair.publicKey, publicKeyB64, privateKey } };
}

/** Opens a stored key pair. A wrong passphrase, a swapped public key or a tampered record all fail the same way. */
export async function unlockIdentity(ctx: IdentityContext, record: IdentityRecord, passphrase: string): Promise<UnlockedIdentity> {
  const kek = await deriveKek(passphrase, fromBase64(record.salt), record.iterations);
  const privateKey = await unwrapIdentityKey(ctx, record, kek, false);
  const publicKey = await importPublicKey(record.publicKey);
  return { ...ctx, publicKey, publicKeyB64: record.publicKey, privateKey };
}

/** Re-wraps the same key pair under a new passphrase. Grants stay valid because the public key is unchanged. */
export async function changePassphrase(
  ctx: IdentityContext,
  record: IdentityRecord,
  oldPassphrase: string,
  newPassphrase: string,
): Promise<IdentityRecord> {
  const oldKek = await deriveKek(oldPassphrase, fromBase64(record.salt), record.iterations);
  const extractable = await unwrapIdentityKey(ctx, record, oldKek, true);
  const { record: next } = await wrapIdentity(ctx, extractable, record.publicKey, newPassphrase);
  return next;
}

/** Human-comparable fingerprint: first 128 bits of SHA-256(raw public key), 8 groups of 4 hex digits. */
export async function fingerprint(publicKeyB64: string): Promise<string> {
  const raw = fromBase64(publicKeyB64);
  if (raw.length !== P256_RAW_PUBLIC_BYTES) throw new VaultCryptoError("invalid_input");
  const hex = [...(await sha256(raw)).subarray(0, 16)].map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
  return hex.match(/.{4}/g)!.join(" ");
}

// ---------------------------------------------------------------------------
// Collection keys and grants (sender-authenticated wrapping, see threat model §5.3)
// ---------------------------------------------------------------------------

/** Identifies a collection: every grant, item, file and name is bound to both ids. */
export interface CollectionContext {
  orgId: string;
  /** Random UUID chosen by the browser when the collection is created. */
  collectionId: string;
}

/** A fresh collection key. Extractable so the creator can wrap it for members and the recovery key. */
export async function generateCollectionKey(): Promise<CryptoKey> {
  return subtle().generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
}

export interface WrappedGrant {
  ephemeralPublicKey: string;
  iv: string;
  wrappedKey: string;
}

export interface GrantRecord extends WrappedGrant {
  keyVersion: number;
  senderUserId: string;
  senderPublicKey: string;
}

async function ecdh(privateKey: CryptoKey, publicKey: CryptoKey): Promise<Bytes> {
  return new Uint8Array(await subtle().deriveBits({ name: "ECDH", public: publicKey }, privateKey, 256));
}

/**
 * Who a grant is addressed to. Each kind has its own HKDF info / AAD purpose,
 * so a grant of one kind can never be presented as another:
 *   member   -> "grant"           (recipient id = the member's user id)
 *   recovery -> "recovery-grant"  (recipient id = the recovery key id)
 *   machine  -> "machine-grant"   (recipient id = the machine account id)
 * A new kind of grantee is a new entry here with its own purpose string; the
 * construction is unchanged. The sender is always a member (their user id and
 * identity key).
 */
export const GRANT_PURPOSES = { member: "grant", recovery: "recovery-grant", machine: "machine-grant" } as const;
export type GrantKind = keyof typeof GRANT_PURPOSES;

async function grantKwk(opts: {
  kind: GrantKind;
  ctx: CollectionContext;
  recipientId: string;
  senderUserId: string;
  keyVersion: number;
  ephemeralShared: Bytes;
  staticShared: Bytes;
  ephemeralPublic: Bytes;
  senderPublic: Bytes;
  recipientPublic: Bytes;
}) {
  const purpose = GRANT_PURPOSES[opts.kind];
  if (!purpose) throw new VaultCryptoError("invalid_input");
  const info = aad(
    purpose,
    uuid(opts.ctx.orgId),
    uuid(opts.ctx.collectionId),
    uuid(opts.recipientId),
    uuid(opts.senderUserId),
    positiveInt(opts.keyVersion),
  );
  const salt = await sha256(concat(opts.ephemeralPublic, opts.senderPublic, opts.recipientPublic));
  const base = await subtle().importKey("raw", concat(opts.ephemeralShared, opts.staticShared), "HKDF", false, ["deriveKey"]);
  const kwk = await subtle().deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["wrapKey", "unwrapKey"],
  );
  return { kwk, info };
}

/**
 * Wraps collection key `key` (version `keyVersion`) for any kind of recipient,
 * authenticated by the sender's identity key. Context:
 * "varn-vault/v1/<purpose>|org|collection|recipient|sender|keyVersion".
 */
export async function wrapCollectionKey(opts: {
  kind: GrantKind;
  ctx: CollectionContext;
  keyVersion: number;
  key: CryptoKey;
  sender: UnlockedIdentity;
  recipientId: string;
  recipientPublicKey: string;
}): Promise<WrappedGrant> {
  if (opts.sender.orgId !== opts.ctx.orgId) throw new VaultCryptoError("invalid_input");
  const recipient = await importPublicKey(opts.recipientPublicKey);
  const eph = (await subtle().generateKey(ECDH_P256, true, ["deriveBits"])) as CryptoKeyPair;
  const ephemeralPublic = new Uint8Array(await subtle().exportKey("raw", eph.publicKey));
  const { kwk, info } = await grantKwk({
    kind: opts.kind,
    ctx: opts.ctx,
    recipientId: opts.recipientId,
    senderUserId: opts.sender.userId,
    keyVersion: opts.keyVersion,
    ephemeralShared: await ecdh(eph.privateKey, recipient),
    staticShared: await ecdh(opts.sender.privateKey, recipient),
    ephemeralPublic,
    senderPublic: fromBase64(opts.sender.publicKeyB64),
    recipientPublic: fromBase64(opts.recipientPublicKey),
  });
  const iv = randomBytes(IV_BYTES);
  const wrapped = await subtle().wrapKey("raw", opts.key, kwk, { name: "AES-GCM", iv, additionalData: info });
  return { ephemeralPublicKey: toBase64(ephemeralPublic), iv: toBase64(iv), wrappedKey: toBase64(wrapped) };
}

/**
 * Opens a grant of any kind with the recipient's private key. Fails with
 * `grant_invalid` if any stored field, the sender's key, the kind or the
 * context (organisation, collection, recipient, key version) does not match.
 */
export async function openGrant(opts: {
  kind: GrantKind;
  ctx: CollectionContext;
  recipientId: string;
  privateKey: CryptoKey;
  recipientPublicKey: string;
  grant: GrantRecord;
  extractable: boolean;
}): Promise<CryptoKey> {
  const { grant } = opts;
  try {
    const ephemeral = await importPublicKey(grant.ephemeralPublicKey);
    const sender = await importPublicKey(grant.senderPublicKey);
    const { kwk, info } = await grantKwk({
      kind: opts.kind,
      ctx: opts.ctx,
      recipientId: opts.recipientId,
      senderUserId: grant.senderUserId,
      keyVersion: grant.keyVersion,
      ephemeralShared: await ecdh(opts.privateKey, ephemeral),
      staticShared: await ecdh(opts.privateKey, sender),
      ephemeralPublic: fromBase64(grant.ephemeralPublicKey),
      senderPublic: fromBase64(grant.senderPublicKey),
      recipientPublic: fromBase64(opts.recipientPublicKey),
    });
    return await subtle().unwrapKey(
      "raw",
      fromBase64(grant.wrappedKey),
      kwk,
      { name: "AES-GCM", iv: fromBase64(grant.iv), additionalData: info },
      { name: "AES-GCM", length: 256 },
      opts.extractable,
      ["encrypt", "decrypt"],
    );
  } catch {
    throw new VaultCryptoError("grant_invalid");
  }
}

/** Member grant: wraps a collection key for a member's public key. */
export async function wrapCollectionKeyFor(opts: {
  ctx: CollectionContext;
  keyVersion: number;
  key: CryptoKey;
  sender: UnlockedIdentity;
  recipientUserId: string;
  recipientPublicKey: string;
}): Promise<WrappedGrant> {
  return wrapCollectionKey({ ...opts, kind: "member", recipientId: opts.recipientUserId });
}

/** Opens a member grant addressed to `identity` for one collection. */
export async function unwrapCollectionKey(opts: {
  identity: UnlockedIdentity;
  collectionId: string;
  grant: GrantRecord;
  extractable: boolean;
}): Promise<CryptoKey> {
  const { identity } = opts;
  return openGrant({
    kind: "member",
    ctx: { orgId: identity.orgId, collectionId: opts.collectionId },
    recipientId: identity.userId,
    privateKey: identity.privateKey,
    recipientPublicKey: identity.publicKeyB64,
    grant: opts.grant,
    extractable: opts.extractable,
  });
}

// ---------------------------------------------------------------------------
// Items, files and collection names
// ---------------------------------------------------------------------------

export interface ItemContext extends CollectionContext {
  itemId: string;
  version: number;
  keyVersion: number;
}

export interface FileContext extends CollectionContext {
  itemId: string;
  keyVersion: number;
}

/** A collection's name is versioned like an item: rename and rotation bump `version`. */
export interface CollectionNameContext extends CollectionContext {
  version: number;
  keyVersion: number;
}

export interface Encrypted {
  iv: string;
  ciphertext: string;
}

const itemAad = (ctx: ItemContext) =>
  aad("item", uuid(ctx.orgId), uuid(ctx.collectionId), uuid(ctx.itemId), positiveInt(ctx.version), positiveInt(ctx.keyVersion));
const fileAad = (ctx: FileContext) =>
  aad("file", uuid(ctx.orgId), uuid(ctx.collectionId), uuid(ctx.itemId), positiveInt(ctx.keyVersion));
const collectionNameAad = (ctx: CollectionNameContext) =>
  aad("collection-name", uuid(ctx.orgId), uuid(ctx.collectionId), positiveInt(ctx.version), positiveInt(ctx.keyVersion));

async function seal(key: CryptoKey, plaintext: Bytes, additionalData: Bytes): Promise<Encrypted> {
  const iv = randomBytes(IV_BYTES);
  const ciphertext = await subtle().encrypt({ name: "AES-GCM", iv, additionalData }, key, plaintext);
  return { iv: toBase64(iv), ciphertext: toBase64(ciphertext) };
}

async function open(key: CryptoKey, enc: Encrypted, additionalData: Bytes): Promise<Bytes> {
  const iv = fromBase64(enc.iv);
  if (iv.length !== IV_BYTES) throw new VaultCryptoError("decrypt_failed");
  try {
    return new Uint8Array(await subtle().decrypt({ name: "AES-GCM", iv, additionalData }, key, fromBase64(enc.ciphertext)));
  } catch {
    throw new VaultCryptoError("decrypt_failed");
  }
}

function padTo(bytes: Bytes, block: number, fill: number): Bytes {
  const length = Math.max(block, Math.ceil(bytes.length / block) * block);
  const out = new Uint8Array(length).fill(fill);
  out.set(bytes);
  return out;
}

export async function encryptItem(key: CryptoKey, ctx: ItemContext, payload: VaultItemPayload): Promise<Encrypted> {
  const parsed = vaultItemPayloadSchema.safeParse(payload);
  if (!parsed.success) throw new VaultCryptoError("invalid_input");
  // Trailing spaces are JSON whitespace, so the padded text still parses.
  const padded = padTo(utf8(JSON.stringify(parsed.data)), ITEM_PADDING_BYTES, 0x20);
  if (padded.length > VAULT_LIMITS.itemPlaintextMaxBytes) throw new VaultCryptoError("too_large");
  return seal(key, padded, itemAad(ctx));
}

export async function decryptItem(key: CryptoKey, ctx: ItemContext, enc: Encrypted): Promise<VaultItemPayload> {
  const plaintext = await open(key, enc, itemAad(ctx));
  let json: unknown;
  try {
    json = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plaintext));
  } catch {
    throw new VaultCryptoError("integrity");
  }
  const parsed = vaultItemPayloadSchema.safeParse(json);
  if (!parsed.success) throw new VaultCryptoError("integrity");
  return parsed.data;
}

/** Encrypts a file; the returned size and hash go into the item payload, which binds the file to the item. */
export async function encryptFile(
  key: CryptoKey,
  ctx: FileContext,
  bytes: Uint8Array,
): Promise<{ encrypted: Encrypted; size: number; sha256: string }> {
  if (bytes.length > VAULT_LIMITS.fileMaxBytes) throw new VaultCryptoError("too_large");
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  const encrypted = await seal(key, padTo(copy, FILE_PADDING_BYTES, 0), fileAad(ctx));
  return { encrypted, size: bytes.length, sha256: await sha256Hex(copy) };
}

export async function decryptFile(
  key: CryptoKey,
  ctx: FileContext,
  enc: Encrypted,
  meta: Pick<VaultFileMeta, "size" | "sha256">,
): Promise<Uint8Array> {
  const padded = await open(key, enc, fileAad(ctx));
  if (meta.size > padded.length) throw new VaultCryptoError("integrity");
  const bytes = padded.slice(0, meta.size);
  if ((await sha256Hex(bytes)) !== meta.sha256) throw new VaultCryptoError("integrity");
  return bytes;
}

/** Encrypts a collection's name (padded JSON {v:1, name}); the server never sees collection names. */
export async function encryptCollectionName(key: CryptoKey, ctx: CollectionNameContext, name: string): Promise<Encrypted> {
  const parsed = collectionNamePayloadSchema.safeParse({ v: 1, name });
  if (!parsed.success) throw new VaultCryptoError("invalid_input");
  const padded = padTo(utf8(JSON.stringify(parsed.data)), COLLECTION_NAME_PADDING_BYTES, 0x20);
  return seal(key, padded, collectionNameAad(ctx));
}

export async function decryptCollectionName(key: CryptoKey, ctx: CollectionNameContext, enc: Encrypted): Promise<string> {
  const plaintext = await open(key, enc, collectionNameAad(ctx));
  let json: unknown;
  try {
    json = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plaintext));
  } catch {
    throw new VaultCryptoError("integrity");
  }
  const parsed = collectionNamePayloadSchema.safeParse(json);
  if (!parsed.success) throw new VaultCryptoError("integrity");
  return parsed.data.name;
}

const PASSWORD_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_.!?#%+=";

/** A random password from an unambiguous alphabet, without modulo bias (rejection sampling). */
export function generatePassword(length = 24): string {
  if (!Number.isSafeInteger(length) || length < 12 || length > 128) throw new VaultCryptoError("invalid_input");
  const n = PASSWORD_ALPHABET.length;
  const limit = 256 - (256 % n);
  let out = "";
  while (out.length < length) {
    for (const byte of randomBytes(length * 2)) {
      if (byte < limit && out.length < length) out += PASSWORD_ALPHABET[byte % n];
    }
  }
  return out;
}

/**
 * Rotation and move helper: decrypts with the old key/context and encrypts
 * with the new one. Moving an item to another collection is the same
 * operation with the target collection's key and id in `to.ctx`.
 */
export async function reencryptItem(
  from: { key: CryptoKey; ctx: ItemContext },
  to: { key: CryptoKey; ctx: ItemContext },
  enc: Encrypted,
): Promise<{ payload: VaultItemPayload; encrypted: Encrypted }> {
  const payload = await decryptItem(from.key, from.ctx, enc);
  return { payload, encrypted: await encryptItem(to.key, to.ctx, payload) };
}

export async function reencryptFile(
  from: { key: CryptoKey; ctx: FileContext },
  to: { key: CryptoKey; ctx: FileContext },
  enc: Encrypted,
  meta: Pick<VaultFileMeta, "size" | "sha256">,
): Promise<Encrypted> {
  const bytes = await decryptFile(from.key, from.ctx, enc, meta);
  return (await encryptFile(to.key, to.ctx, bytes)).encrypted;
}

// ---------------------------------------------------------------------------
// Organisation recovery key (optional; threat model §5.6)
//
//   recovery key pair  = ECDH P-256, generated in the owner's browser
//   recovery code      = Crockford base32( d ‖ checksum ), d = the 32-byte private scalar,
//                        checksum = SHA-256("varn-vault/v1/recovery-code|" ‖ d)[0..3]
//                        → 56 characters, shown as 14 groups of 4
//   recovery grants    = every collection's current key wrapped for the recovery public key,
//                        exactly like a member grant but with purpose "recovery-grant" and the
//                        recovery key id as recipient (one grant per collection and key version)
//   attestation        = AES-GCM(collection key v, raw recovery public key,
//                        AAD = "varn-vault/v1/recovery-key|org|collection|recovery id|v"): proves to
//                        any holder of that collection key that a holder of it registered this
//                        public key, so the server cannot substitute its own key when a collection
//                        is rotated or created
//   recovery token     = HKDF-SHA-256(d, info = "varn-vault/v1/recovery-token|org|recovery id");
//                        the server stores SHA-256(token) and checks the token at recovery, so
//                        nobody without the code can use the recovery RPC. The token is one-way
//                        from d and opens nothing.
// The code and d never leave the browser.
// ---------------------------------------------------------------------------

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const RECOVERY_SECRET_BYTES = 32;
const RECOVERY_CHECKSUM_BYTES = 3;
/** 35 bytes = 280 bits = exactly 56 base32 characters. */
export const RECOVERY_CODE_LENGTH = ((RECOVERY_SECRET_BYTES + RECOVERY_CHECKSUM_BYTES) * 8) / 5;
export const RECOVERY_CODE_GROUP = 4;

function base32Encode(bytes: Uint8Array): string {
  let out = "";
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += CROCKFORD[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
    buffer &= (1 << bits) - 1;
  }
  if (bits > 0) out += CROCKFORD[(buffer << (5 - bits)) & 31];
  return out;
}

function base32Decode(text: string): Bytes | null {
  const out: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const ch of text) {
    const value = CROCKFORD.indexOf(ch);
    if (value < 0) return null;
    buffer = (buffer << 5) | value;
    bits += 5;
    if (bits >= 8) {
      out.push((buffer >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
    buffer &= (1 << bits) - 1;
  }
  return Uint8Array.from(out);
}

/** Upper-cases, drops spaces and hyphens, and maps the look-alikes Crockford allows (O→0, I/L→1). */
export function normalizeRecoveryCode(code: string): string {
  return code.toUpperCase().replace(/[\s-]/g, "").replace(/O/g, "0").replace(/[IL]/g, "1");
}

/** Splits a normalised code into groups for display and printing. */
export function formatRecoveryCode(code: string): string {
  return normalizeRecoveryCode(code).match(new RegExp(`.{1,${RECOVERY_CODE_GROUP}}`, "g"))?.join("-") ?? "";
}

async function recoveryChecksum(secret: Bytes): Promise<Bytes> {
  return (await sha256(concat(utf8("varn-vault/v1/recovery-code|"), secret))).slice(0, RECOVERY_CHECKSUM_BYTES);
}

/** Encodes a 32-byte recovery secret as a grouped, check-summed code. */
export async function encodeRecoveryCode(secret: Uint8Array): Promise<string> {
  if (secret.length !== RECOVERY_SECRET_BYTES) throw new VaultCryptoError("invalid_input");
  const copy = new Uint8Array(secret.length);
  copy.set(secret);
  return formatRecoveryCode(base32Encode(concat(copy, await recoveryChecksum(copy))));
}

/** Decodes a code typed by a person. Any typo the checksum catches, or a wrong length, gives `recovery_code_invalid`. */
export async function decodeRecoveryCode(code: string): Promise<Bytes> {
  if (typeof code !== "string") throw new VaultCryptoError("recovery_code_invalid");
  const normalized = normalizeRecoveryCode(code);
  if (normalized.length !== RECOVERY_CODE_LENGTH) throw new VaultCryptoError("recovery_code_invalid");
  const bytes = base32Decode(normalized);
  if (!bytes || bytes.length !== RECOVERY_SECRET_BYTES + RECOVERY_CHECKSUM_BYTES) throw new VaultCryptoError("recovery_code_invalid");
  const secret = bytes.slice(0, RECOVERY_SECRET_BYTES);
  const checksum = await recoveryChecksum(secret);
  if (checksum.some((b, i) => b !== bytes[RECOVERY_SECRET_BYTES + i])) throw new VaultCryptoError("recovery_code_invalid");
  return secret;
}


export interface RecoveryContext {
  orgId: string;
  /** Random UUID chosen by the browser when the recovery key is created; changes on replacement. */
  recoveryId: string;
}

/** A collection key of a given version, as held in an unlocked tab. */
export interface CollectionKeyRef {
  collectionId: string;
  keyVersion: number;
  key: CryptoKey;
}

/** What the browser sends the server for the recovery holder of one collection and key version. */
export interface RecoveryWrap {
  collectionId: string;
  keyVersion: number;
  grant: WrappedGrant;
  attestation: Encrypted;
}

const attestationAad = (ctx: RecoveryContext, collectionId: string, keyVersion: number) =>
  aad("recovery-key", uuid(ctx.orgId), uuid(collectionId), uuid(ctx.recoveryId), positiveInt(keyVersion));

/** Binds a recovery public key to collection key `keyVersion` (see the section comment). */
export async function attestRecoveryKey(
  key: CryptoKey,
  ctx: RecoveryContext,
  collectionId: string,
  keyVersion: number,
  publicKeyB64: string,
): Promise<Encrypted> {
  await importPublicKey(publicKeyB64);
  return seal(key, fromBase64(publicKeyB64), attestationAad(ctx, collectionId, keyVersion));
}

/** Throws `integrity` unless `attestation` was made with `key` for exactly this recovery key, collection and version. */
export async function verifyRecoveryAttestation(
  key: CryptoKey,
  ctx: RecoveryContext,
  collectionId: string,
  keyVersion: number,
  publicKeyB64: string,
  attestation: Encrypted,
): Promise<void> {
  let plaintext: Bytes;
  try {
    plaintext = await open(key, attestation, attestationAad(ctx, collectionId, keyVersion));
  } catch {
    throw new VaultCryptoError("integrity");
  }
  const expected = fromBase64(publicKeyB64);
  if (plaintext.length !== expected.length || plaintext.some((b, i) => b !== expected[i])) throw new VaultCryptoError("integrity");
}

async function recoveryToken(ctx: RecoveryContext, secret: Bytes): Promise<string> {
  const base = await subtle().importKey("raw", secret, "HKDF", false, ["deriveBits"]);
  const bits = await subtle().deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: aad("recovery-token", uuid(ctx.orgId), uuid(ctx.recoveryId)) },
    base,
    256,
  );
  return toBase64(bits);
}

/** SHA-256 of the token, base64: what the server stores to check a recovery attempt. */
export async function recoveryVerifier(token: string): Promise<string> {
  return toBase64(await sha256(fromBase64(token)));
}

/**
 * Wraps one collection key version for the recovery holder and attests the
 * recovery public key under it. Callers that did not just create the recovery
 * key must verify an existing attestation first (rewrapForRecovery does).
 */
export async function wrapCollectionKeyForRecovery(opts: {
  ctx: RecoveryContext;
  collection: CollectionKeyRef;
  sender: UnlockedIdentity;
  recoveryPublicKey: string;
}): Promise<RecoveryWrap> {
  if (opts.ctx.orgId !== opts.sender.orgId) throw new VaultCryptoError("invalid_input");
  const { collectionId, keyVersion, key } = opts.collection;
  const grant = await wrapCollectionKey({
    kind: "recovery",
    ctx: { orgId: opts.ctx.orgId, collectionId },
    keyVersion,
    key,
    sender: opts.sender,
    recipientId: opts.ctx.recoveryId,
    recipientPublicKey: opts.recoveryPublicKey,
  });
  const attestation = await attestRecoveryKey(key, opts.ctx, collectionId, keyVersion, opts.recoveryPublicKey);
  return { collectionId, keyVersion, grant, attestation };
}

export interface NewRecoveryKey {
  /** Shown to the owner once; never sent anywhere. */
  code: string;
  recoveryId: string;
  publicKey: string;
  verifier: string;
  /** One per collection, in the order given. */
  grants: RecoveryWrap[];
}

/**
 * Creates the organisation's recovery key in the browser: a fresh key pair,
 * the current key of every collection wrapped for it with an attestation each,
 * and the verifier for the server. Only `code` contains the private key.
 */
export async function createRecoveryKey(opts: {
  orgId: string;
  collections: CollectionKeyRef[];
  sender: UnlockedIdentity;
}): Promise<NewRecoveryKey> {
  if (opts.collections.length === 0 || new Set(opts.collections.map((c) => c.collectionId)).size !== opts.collections.length) {
    throw new VaultCryptoError("invalid_input");
  }
  const ctx: RecoveryContext = { orgId: opts.orgId, recoveryId: globalThis.crypto.randomUUID() };
  const pair = (await subtle().generateKey(ECDH_P256, true, ["deriveBits"])) as CryptoKeyPair;
  const publicKey = toBase64(await subtle().exportKey("raw", pair.publicKey));
  const jwk = await subtle().exportKey("jwk", pair.privateKey);
  const secret = fromBase64Url(jwk.d ?? "");
  if (secret.length !== RECOVERY_SECRET_BYTES) throw new VaultCryptoError("invalid_input");
  try {
    const grants: RecoveryWrap[] = [];
    for (const collection of opts.collections) {
      grants.push(await wrapCollectionKeyForRecovery({ ctx, collection, sender: opts.sender, recoveryPublicKey: publicKey }));
    }
    const verifier = await recoveryVerifier(await recoveryToken(ctx, secret));
    return { code: await encodeRecoveryCode(secret), recoveryId: ctx.recoveryId, publicKey, verifier, grants };
  } finally {
    secret.fill(0);
  }
}

/**
 * Opens recovery grants with a code typed by a person. Returns the collection
 * keys and the token the server needs to accept the recovery. A malformed
 * code, a code for another recovery key, a swapped public key or a tampered
 * grant (including one moved to another collection) all fail with
 * `recovery_code_invalid`.
 */
export async function openWithRecoveryCode(opts: {
  ctx: RecoveryContext;
  code: string;
  recoveryPublicKey: string;
  grants: { collectionId: string; grant: GrantRecord }[];
  extractable: boolean;
}): Promise<{ keys: CollectionKeyRef[]; token: string }> {
  const secret = await decodeRecoveryCode(opts.code);
  try {
    if (opts.grants.length === 0) throw new VaultCryptoError("recovery_code_invalid");
    const raw = fromBase64(opts.recoveryPublicKey);
    if (raw.length !== P256_RAW_PUBLIC_BYTES || raw[0] !== 0x04) throw new VaultCryptoError("recovery_code_invalid");
    const privateKey = await subtle().importKey(
      "jwk",
      { kty: "EC", crv: "P-256", x: toBase64Url(raw.subarray(1, 33)), y: toBase64Url(raw.subarray(33, 65)), d: toBase64Url(secret), ext: false },
      ECDH_P256,
      false,
      ["deriveBits"],
    );
    const keys: CollectionKeyRef[] = [];
    for (const { collectionId, grant } of opts.grants) {
      const key = await openGrant({
        kind: "recovery",
        ctx: { orgId: opts.ctx.orgId, collectionId },
        recipientId: opts.ctx.recoveryId,
        privateKey,
        recipientPublicKey: opts.recoveryPublicKey,
        grant,
        extractable: opts.extractable,
      });
      keys.push({ collectionId, keyVersion: grant.keyVersion, key });
    }
    return { keys, token: await recoveryToken(opts.ctx, secret) };
  } catch {
    throw new VaultCryptoError("recovery_code_invalid");
  } finally {
    secret.fill(0);
  }
}

/**
 * Gives the recovery holder a collection key it does not have yet, without
 * trusting the server's copy of the recovery public key: first checks an
 * existing attestation of that public key under a key the caller already holds
 * (`from`), then wraps `to` for the same recovery key and attests it under `to`.
 *   - Rotation: `from` = the collection's current key, `to` = its new version.
 *   - New collection: `from` = any collection the caller holds, `to` = the new collection's key.
 * A public key the server swapped in fails the check with `integrity`.
 */
export async function rewrapForRecovery(opts: {
  ctx: RecoveryContext;
  recoveryPublicKey: string;
  sender: UnlockedIdentity;
  from: CollectionKeyRef & { attestation: Encrypted };
  to: CollectionKeyRef;
}): Promise<RecoveryWrap> {
  const { from } = opts;
  await verifyRecoveryAttestation(from.key, opts.ctx, from.collectionId, from.keyVersion, opts.recoveryPublicKey, from.attestation);
  return wrapCollectionKeyForRecovery({ ctx: opts.ctx, collection: opts.to, sender: opts.sender, recoveryPublicKey: opts.recoveryPublicKey });
}

// ---------------------------------------------------------------------------
// Machine accounts (design doc §3.2; threat model §5.9)
//
//   machine key pair = ECDH P-256, generated in the creating admin's browser
//   machine_id       = random UUID chosen by that browser
//   token            = "varn_mt_" + Crockford base32( version(1) ‖ org_id(16) ‖ machine_id(16) ‖ d(32) ‖ checksum(3) )
//                      checksum = SHA-256("varn-vault/v1/machine-token|" ‖ version ‖ org_id ‖ machine_id ‖ d)[0..3]
//                      → 68 bytes = 109 characters after the prefix (the last character carries one zero pad bit)
//   auth_secret      = HKDF-SHA-256(d, salt = empty, info = "varn-vault/v1/machine-auth|org_id|machine_id") (32 bytes)
//   bearer           = base64url(auth_secret) without padding (43 characters), sent as `Authorization: Bearer …`
//   verifier         = base64(SHA-256(auth_secret)); the only thing Värn stores to recognise the machine
//   grants           = each chosen collection key wrapped as in §5.3 with purpose "machine-grant":
//                      "varn-vault/v1/machine-grant|org_id|collection_id|machine_id|sender_user_id|v"
//   attestation      = per grant: AES-GCM(collection key v, raw machine public key,
//                      AAD = "varn-vault/v1/machine-key|org_id|collection_id|machine_id|v"), checked
//                      by the browser before it wraps any further key for the machine (rotation,
//                      more collections), so only a holder of the key can register a machine
//
// Two secrets come from one token: the machine sends only the bearer (which
// opens nothing) and keeps d to open its grants. The token and d never reach
// Värn. Pure Web Crypto, no DOM APIs: the `varn` CLI (Node 20+) uses this too.
// ---------------------------------------------------------------------------

export const MACHINE_TOKEN_PREFIX = "varn_mt_";
export const MACHINE_TOKEN_VERSION = 1;
const MACHINE_SECRET_BYTES = 32;
const MACHINE_CHECKSUM_BYTES = 3;
const MACHINE_PAYLOAD_BYTES = 1 + 16 + 16 + MACHINE_SECRET_BYTES;
const MACHINE_TOKEN_BYTES = MACHINE_PAYLOAD_BYTES + MACHINE_CHECKSUM_BYTES;
/** Characters after the prefix: ceil(68 * 8 / 5) = 109. */
export const MACHINE_TOKEN_BODY_LENGTH = Math.ceil((MACHINE_TOKEN_BYTES * 8) / 5);
export const MACHINE_TOKEN_LENGTH = MACHINE_TOKEN_PREFIX.length + MACHINE_TOKEN_BODY_LENGTH;

export interface MachineContext {
  orgId: string;
  /** Random UUID chosen by the creating browser; bound into the token, the bearer and every machine grant. */
  machineId: string;
}

/** A parsed token. `secret` is the machine's private scalar d: keep it in memory only. */
export interface MachineToken extends MachineContext {
  version: typeof MACHINE_TOKEN_VERSION;
  secret: Bytes;
}

function uuidToBytes(value: string): Bytes {
  const hex = uuid(value).replace(/-/g, "");
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToUuid(bytes: Uint8Array): string {
  const hex = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

async function machineChecksum(payload: Bytes): Promise<Bytes> {
  return (await sha256(concat(utf8("varn-vault/v1/machine-token|"), payload))).slice(0, MACHINE_CHECKSUM_BYTES);
}

/** Encodes a machine token. Only the creating browser calls this, once. */
export async function encodeMachineToken(ctx: MachineContext, secret: Uint8Array): Promise<string> {
  if (secret.length !== MACHINE_SECRET_BYTES) throw new VaultCryptoError("invalid_input");
  const payload = concat(Uint8Array.of(MACHINE_TOKEN_VERSION), uuidToBytes(ctx.orgId), uuidToBytes(ctx.machineId), secret);
  try {
    return MACHINE_TOKEN_PREFIX + base32Encode(concat(payload, await machineChecksum(payload)));
  } finally {
    payload.fill(0);
  }
}

/**
 * Parses a token as pasted into an environment variable. Surrounding
 * whitespace is ignored and the Crockford look-alikes are accepted
 * (O→0, I/L→1, any case); anything else, including a checksum mismatch, an
 * unknown version or a non-canonical last character, is `machine_token_invalid`.
 */
export async function parseMachineToken(token: string): Promise<MachineToken> {
  if (typeof token !== "string") throw new VaultCryptoError("machine_token_invalid");
  const trimmed = token.trim();
  if (!trimmed.startsWith(MACHINE_TOKEN_PREFIX)) throw new VaultCryptoError("machine_token_invalid");
  const body = normalizeRecoveryCode(trimmed.slice(MACHINE_TOKEN_PREFIX.length));
  if (body.length !== MACHINE_TOKEN_BODY_LENGTH) throw new VaultCryptoError("machine_token_invalid");
  const bytes = base32Decode(body);
  if (!bytes || bytes.length !== MACHINE_TOKEN_BYTES) throw new VaultCryptoError("machine_token_invalid");
  try {
    // 109 characters carry 545 bits for 544: the spare bit must be zero, so every token has one spelling.
    if ((CROCKFORD.indexOf(body[body.length - 1]!) & 1) !== 0) throw new VaultCryptoError("machine_token_invalid");
    const payload = bytes.slice(0, MACHINE_PAYLOAD_BYTES);
    try {
      const checksum = await machineChecksum(payload);
      if (checksum.some((b, i) => b !== bytes[MACHINE_PAYLOAD_BYTES + i])) throw new VaultCryptoError("machine_token_invalid");
      if (payload[0] !== MACHINE_TOKEN_VERSION) throw new VaultCryptoError("machine_token_invalid");
      return {
        version: MACHINE_TOKEN_VERSION,
        orgId: bytesToUuid(payload.subarray(1, 17)),
        machineId: bytesToUuid(payload.subarray(17, 33)),
        secret: payload.slice(33),
      };
    } finally {
      payload.fill(0);
    }
  } finally {
    bytes.fill(0);
  }
}

/** auth_secret = HKDF-SHA-256(d, salt = empty, info = "varn-vault/v1/machine-auth|org|machine"), 32 bytes. */
export async function machineAuthSecret(ctx: MachineContext, secret: Uint8Array): Promise<Bytes> {
  if (secret.length !== MACHINE_SECRET_BYTES) throw new VaultCryptoError("invalid_input");
  const copy = new Uint8Array(secret.length);
  copy.set(secret);
  try {
    const base = await subtle().importKey("raw", copy, "HKDF", false, ["deriveBits"]);
    const bits = await subtle().deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: aad("machine-auth", uuid(ctx.orgId), uuid(ctx.machineId)) },
      base,
      256,
    );
    return new Uint8Array(bits);
  } finally {
    copy.fill(0);
  }
}

/** The value for `Authorization: Bearer …`: base64url(auth_secret) without padding, 43 characters. */
export async function machineBearer(token: MachineToken): Promise<string> {
  const authSecret = await machineAuthSecret(token, token.secret);
  try {
    return toBase64Url(authSecret);
  } finally {
    authSecret.fill(0);
  }
}

/** What Värn stores for a machine: base64(SHA-256(auth_secret)). */
export async function machineVerifier(authSecret: Uint8Array): Promise<string> {
  if (authSecret.length !== 32) throw new VaultCryptoError("invalid_input");
  const copy = new Uint8Array(32);
  copy.set(authSecret);
  return toBase64(await sha256(copy));
}

/** Server side: the verifier for a bearer value, or null if the value is not 32 bytes of base64url. */
export async function machineVerifierFromBearer(bearer: string): Promise<string | null> {
  if (typeof bearer !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(bearer)) return null;
  let raw: Bytes;
  try {
    raw = fromBase64Url(bearer);
  } catch {
    return null;
  }
  if (raw.length !== 32) return null;
  return machineVerifier(raw);
}

/**
 * A collection key wrapped for a machine (one per collection and key version),
 * with an attestation of the machine's public key under that collection key.
 */
export interface MachineWrap {
  collectionId: string;
  keyVersion: number;
  grant: WrappedGrant;
  /** AES-GCM(collection key v, raw machine public key, AAD "varn-vault/v1/machine-key|org|collection|machine|v"). */
  attestation: Encrypted;
}

const machineKeyAad = (ctx: MachineContext, collectionId: string, keyVersion: number) =>
  aad("machine-key", uuid(ctx.orgId), uuid(collectionId), uuid(ctx.machineId), positiveInt(keyVersion));

/**
 * Binds a machine public key to collection key `keyVersion`: only someone who
 * holds that collection key can make it. The browser checks it before wrapping
 * any further key for the machine, so neither the server nor someone with an
 * admin's session but without the key can register a machine key that later
 * receives real collection keys (threat model §5.9, M11).
 */
export async function attestMachineKey(
  key: CryptoKey,
  ctx: MachineContext,
  collectionId: string,
  keyVersion: number,
  publicKeyB64: string,
): Promise<Encrypted> {
  await importPublicKey(publicKeyB64);
  return seal(key, fromBase64(publicKeyB64), machineKeyAad(ctx, collectionId, keyVersion));
}

/** Throws `integrity` unless `attestation` was made with `key` for exactly this machine, public key, collection and version. */
export async function verifyMachineAttestation(
  key: CryptoKey,
  ctx: MachineContext,
  collectionId: string,
  keyVersion: number,
  publicKeyB64: string,
  attestation: Encrypted,
): Promise<void> {
  let plaintext: Bytes;
  try {
    plaintext = await open(key, attestation, machineKeyAad(ctx, collectionId, keyVersion));
  } catch {
    throw new VaultCryptoError("integrity");
  }
  const expected = fromBase64(publicKeyB64);
  if (plaintext.length !== expected.length || plaintext.some((b, i) => b !== expected[i])) throw new VaultCryptoError("integrity");
}

/**
 * Wraps one collection key version for a machine account (authenticated by the
 * sender's identity key) and attests the machine's public key under it. Only
 * for a machine this browser just created: for an existing machine use
 * rewrapForMachine, which checks an existing attestation first.
 */
export async function wrapCollectionKeyForMachine(opts: {
  ctx: MachineContext;
  collection: CollectionKeyRef;
  sender: UnlockedIdentity;
  machinePublicKey: string;
}): Promise<MachineWrap> {
  if (opts.ctx.orgId !== opts.sender.orgId) throw new VaultCryptoError("invalid_input");
  const { collectionId, keyVersion, key } = opts.collection;
  const grant = await wrapCollectionKey({
    kind: "machine",
    ctx: { orgId: opts.ctx.orgId, collectionId },
    keyVersion,
    key,
    sender: opts.sender,
    recipientId: opts.ctx.machineId,
    recipientPublicKey: opts.machinePublicKey,
  });
  const attestation = await attestMachineKey(key, opts.ctx, collectionId, keyVersion, opts.machinePublicKey);
  return { collectionId, keyVersion, grant, attestation };
}

/**
 * Gives an existing machine a collection key without trusting the server's
 * copy of its public key: first checks the attestation of that public key under
 * a collection key this browser holds (`from`), then wraps `to` and attests
 * under `to`. A machine registered without the key (a stolen admin session, or
 * a public key the server swapped in) fails with `integrity` and gets nothing.
 *   - Rotation: `from` = the collection's current key, `to` = its new version.
 *   - More collections: `from` = any collection the machine and this browser both hold.
 */
export async function rewrapForMachine(opts: {
  ctx: MachineContext;
  machinePublicKey: string;
  sender: UnlockedIdentity;
  from: CollectionKeyRef & { attestation: Encrypted };
  to: CollectionKeyRef;
}): Promise<MachineWrap> {
  const { from } = opts;
  await verifyMachineAttestation(from.key, opts.ctx, from.collectionId, from.keyVersion, opts.machinePublicKey, from.attestation);
  return wrapCollectionKeyForMachine({ ctx: opts.ctx, collection: opts.to, sender: opts.sender, machinePublicKey: opts.machinePublicKey });
}

export interface NewMachineAccount {
  /** Shown to the admin once; never sent anywhere. Contains the machine's private key. */
  token: string;
  machineId: string;
  publicKey: string;
  verifier: string;
  /** One per collection, in the order given. */
  grants: MachineWrap[];
}

/**
 * Creates a machine account in the admin's browser: a fresh key pair, the
 * chosen collections' current keys wrapped for it, the verifier for the server
 * and the one-time token. Only `token` contains the private key.
 */
export async function createMachineAccount(opts: {
  orgId: string;
  collections: CollectionKeyRef[];
  sender: UnlockedIdentity;
}): Promise<NewMachineAccount> {
  if (opts.collections.length === 0 || new Set(opts.collections.map((c) => c.collectionId)).size !== opts.collections.length) {
    throw new VaultCryptoError("invalid_input");
  }
  const ctx: MachineContext = { orgId: uuid(opts.orgId), machineId: globalThis.crypto.randomUUID() };
  const pair = (await subtle().generateKey(ECDH_P256, true, ["deriveBits"])) as CryptoKeyPair;
  const publicKey = toBase64(await subtle().exportKey("raw", pair.publicKey));
  const jwk = await subtle().exportKey("jwk", pair.privateKey);
  const secret = fromBase64Url(jwk.d ?? "");
  if (secret.length !== MACHINE_SECRET_BYTES) throw new VaultCryptoError("invalid_input");
  try {
    const grants: MachineWrap[] = [];
    for (const collection of opts.collections) {
      grants.push(await wrapCollectionKeyForMachine({ ctx, collection, sender: opts.sender, machinePublicKey: publicKey }));
    }
    const authSecret = await machineAuthSecret(ctx, secret);
    const verifier = await machineVerifier(authSecret);
    authSecret.fill(0);
    return { token: await encodeMachineToken(ctx, secret), machineId: ctx.machineId, publicKey, verifier, grants };
  } finally {
    secret.fill(0);
  }
}

export interface UnlockedMachine extends MachineContext {
  publicKeyB64: string;
  /** Non-extractable; usable only for ECDH deriveBits. */
  privateKey: CryptoKey;
}

/**
 * Imports the machine's private key from a parsed token and the machine's
 * public key as the read API returns it. A public key that does not belong to
 * the token's private key is refused (`machine_token_invalid`) by Web Crypto
 * implementations that check the point; where one does not, every grant then
 * fails to open, because the public key is part of the HKDF salt.
 */
export async function unlockMachine(token: MachineToken, publicKeyB64: string): Promise<UnlockedMachine> {
  try {
    const raw = fromBase64(publicKeyB64);
    if (raw.length !== P256_RAW_PUBLIC_BYTES || raw[0] !== 0x04) throw new VaultCryptoError("machine_token_invalid");
    const privateKey = await subtle().importKey(
      "jwk",
      { kty: "EC", crv: "P-256", x: toBase64Url(raw.subarray(1, 33)), y: toBase64Url(raw.subarray(33, 65)), d: toBase64Url(token.secret), ext: false },
      ECDH_P256,
      false,
      ["deriveBits"],
    );
    return { orgId: token.orgId, machineId: token.machineId, publicKeyB64, privateKey };
  } catch {
    throw new VaultCryptoError("machine_token_invalid");
  }
}

/** Opens a machine grant for one collection (`grant_invalid` on any mismatch: another sender, collection, machine, organisation or version). */
export async function openMachineGrant(opts: {
  machine: UnlockedMachine;
  collectionId: string;
  grant: GrantRecord;
  extractable?: boolean;
}): Promise<CryptoKey> {
  return openGrant({
    kind: "machine",
    ctx: { orgId: opts.machine.orgId, collectionId: opts.collectionId },
    recipientId: opts.machine.machineId,
    privateKey: opts.machine.privateKey,
    recipientPublicKey: opts.machine.publicKeyB64,
    grant: opts.grant,
    extractable: opts.extractable ?? false,
  });
}
