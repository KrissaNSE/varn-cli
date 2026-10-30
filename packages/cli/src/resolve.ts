/**
 * Resolving secret references on the machine (design doc §3.3):
 *
 *   1. parse the token, derive the bearer value (the token's private key d never leaves the process);
 *   2. fetch only what is needed: the referenced collections by id when every
 *      reference names its collection by id, otherwise every collection the
 *      machine holds (names are encrypted, so the server cannot match them);
 *   3. check that the response is for the token's organisation and machine,
 *      import d with the machine's public key, open the grants
 *      (sender-authenticated), decrypt collection names and items, and match
 *      names locally.
 *
 * Nothing is cached or written to disk. Decrypted values only live in memory.
 */
import {
  VaultCryptoError,
  decryptCollectionName,
  decryptItem,
  machineBearer,
  openMachineGrant,
  unlockMachine,
  type MachineToken,
  type UnlockedMachine,
} from "../../../src/domain/vault/crypto";
import type { MachineCollection, MachineItem, MachineReadResponse } from "../../../src/domain/vault/machine-api";
import type { VaultItemPayload } from "../../../src/domain/vault/model";
import { fetchCollections } from "./api";
import { CliError, EXIT } from "./errors";
import { nameKey, type SecretReference, type Selector } from "./reference";

export interface ResolvedSecret {
  reference: SecretReference;
  value: string;
  collectionId: string;
  itemId: string;
  itemVersion: number;
  updatedAt: string;
}

export interface ResolveOptions {
  token: MachineToken;
  origin: string;
  fetch?: typeof globalThis.fetch;
  warn: (message: string) => void;
  /** Days before expiry at which to warn that the machine account expires soon. */
  expiryWarningDays?: number;
  now?: () => Date;
}

function describe(selector: Selector): string {
  return selector.kind === "id" ? `id:${selector.id}` : JSON.stringify(selector.name);
}

/** Lazily decrypts what the references need, and remembers it for the other references. */
class Vault {
  private keys = new Map<string, Promise<CryptoKey>>();
  private names = new Map<string, Promise<string | null>>();
  private items = new Map<string, Promise<VaultItemPayload | null>>();

  constructor(
    private readonly response: MachineReadResponse,
    private readonly machine: UnlockedMachine,
    private readonly warn: (message: string) => void,
  ) {}

  /** The collection key of one version, opened from this machine's grant. */
  private key(collection: MachineCollection, keyVersion: number): Promise<CryptoKey> {
    const cacheKey = `${collection.id}|${keyVersion}`;
    let key = this.keys.get(cacheKey);
    if (!key) {
      const grant = collection.grants.find((g) => g.key_version === keyVersion);
      key = grant
        ? openMachineGrant({
            machine: this.machine,
            collectionId: collection.id,
            grant: {
              keyVersion: grant.key_version,
              ephemeralPublicKey: grant.ephemeral_public_key,
              iv: grant.iv,
              wrappedKey: grant.wrapped_key,
              senderUserId: grant.sender_user_id,
              senderPublicKey: grant.sender_public_key,
            },
          })
        : Promise.reject(new VaultCryptoError("grant_invalid"));
      // Avoid an unhandled rejection while the promise sits in the cache.
      key.catch(() => undefined);
      this.keys.set(cacheKey, key);
    }
    return key;
  }

  /** The collection's name, or null (with one warning) if it does not decrypt. */
  name(collection: MachineCollection): Promise<string | null> {
    let name = this.names.get(collection.id);
    if (!name) {
      name = (async () => {
        try {
          const key = await this.key(collection, collection.key_version);
          return await decryptCollectionName(
            key,
            { orgId: this.machine.orgId, collectionId: collection.id, version: collection.name.version, keyVersion: collection.key_version },
            collection.name,
          );
        } catch {
          this.warn(`Collection ${collection.id} could not be decrypted with this machine's grant; it is skipped.`);
          return null;
        }
      })();
      this.names.set(collection.id, name);
    }
    return name;
  }

  /** The item's plaintext, or null (with one warning) if it does not decrypt. */
  item(collection: MachineCollection, item: MachineItem): Promise<VaultItemPayload | null> {
    let payload = this.items.get(item.id);
    if (!payload) {
      payload = (async () => {
        try {
          const key = await this.key(collection, item.key_version);
          return await decryptItem(
            key,
            { orgId: this.machine.orgId, collectionId: collection.id, itemId: item.id, version: item.version, keyVersion: item.key_version },
            item,
          );
        } catch {
          this.warn(`Item ${item.id} in collection ${collection.id} could not be decrypted; it is skipped.`);
          return null;
        }
      })();
      this.items.set(item.id, payload);
    }
    return payload;
  }

  async collection(ref: SecretReference): Promise<MachineCollection> {
    const selector = ref.collection;
    if (selector.kind === "id") {
      const found = this.response.collections.find((c) => c.id === selector.id);
      if (!found) {
        throw new CliError(EXIT.notFound, `${ref.raw}: this machine account cannot read collection ${selector.id}.`);
      }
      return found;
    }
    const wanted = nameKey(selector.name);
    const named = await Promise.all(this.response.collections.map(async (c) => ({ c, name: await this.name(c) })));
    const matches = named.filter((n) => n.name !== null && nameKey(n.name) === wanted).map((n) => n.c);
    if (matches.length > 1) {
      throw new CliError(
        EXIT.ambiguous,
        `${ref.raw}: ${matches.length} collections are named ${describe(selector)} (${matches.map((c) => c.id).join(", ")}). Refer to the collection by id instead, for example varn://${ref.org}/id:${matches[0]!.id}/…`,
      );
    }
    if (matches.length === 0) {
      const undecryptable = named.filter((n) => n.name === null).length;
      throw new CliError(
        EXIT.notFound,
        `${ref.raw}: this machine account has no collection named ${describe(selector)}${
          undecryptable ? ` (${undecryptable} collection(s) could not be decrypted)` : ""
        }. Check the name, or grant the machine access to the collection in Värn.`,
      );
    }
    return matches[0]!;
  }

  async resolve(ref: SecretReference): Promise<ResolvedSecret> {
    const collection = await this.collection(ref);
    const selector = ref.item;
    let item: MachineItem;
    let payload: VaultItemPayload;
    if (selector.kind === "id") {
      const found = collection.items.find((i) => i.id === selector.id);
      if (!found) throw new CliError(EXIT.notFound, `${ref.raw}: collection ${collection.id} has no item ${selector.id}.`);
      const decrypted = await this.item(collection, found);
      if (!decrypted) throw new CliError(EXIT.decrypt, `${ref.raw}: item ${found.id} could not be decrypted.`);
      item = found;
      payload = decrypted;
    } else {
      const wanted = nameKey(selector.name);
      const decrypted = await Promise.all(collection.items.map(async (i) => ({ i, payload: await this.item(collection, i) })));
      const matches = decrypted.filter((d): d is { i: MachineItem; payload: VaultItemPayload } => d.payload !== null && nameKey(d.payload.name) === wanted);
      if (matches.length > 1) {
        throw new CliError(
          EXIT.ambiguous,
          `${ref.raw}: ${matches.length} items in the collection are named ${describe(selector)} (${matches.map((m) => m.i.id).join(", ")}). Rename one, or refer to the item by id, for example …/id:${matches[0]!.i.id}/${ref.field}`,
        );
      }
      if (matches.length === 0) {
        const undecryptable = decrypted.filter((d) => d.payload === null).length;
        throw new CliError(
          EXIT.notFound,
          `${ref.raw}: no item named ${describe(selector)} in collection ${collection.id}${undecryptable ? ` (${undecryptable} item(s) could not be decrypted)` : ""}.`,
        );
      }
      item = matches[0]!.i;
      payload = matches[0]!.payload;
    }
    const value = payload[ref.field];
    if (value === "") throw new CliError(EXIT.notFound, `${ref.raw}: the item's ${ref.field} is empty.`);
    return { reference: ref, value, collectionId: collection.id, itemId: item.id, itemVersion: item.version, updatedAt: item.updated_at };
  }
}

/**
 * Resolves every reference with one API request (or one per 100 collection
 * ids). Returns the values in the order of `refs`.
 */
export async function resolveReferences(refs: SecretReference[], opts: ResolveOptions): Promise<ResolvedSecret[]> {
  if (refs.length === 0) return [];
  const { token } = opts;

  const byId = refs.every((r) => r.collection.kind === "id");
  const ids = byId ? refs.map((r) => (r.collection as { id: string }).id) : undefined;
  const response = await fetchCollections({ origin: opts.origin, bearer: await machineBearer(token), ids, fetch: opts.fetch });

  if (response.organization.id !== token.orgId || response.machine.id !== token.machineId) {
    throw new CliError(EXIT.decrypt, "The API answered for another organisation or machine account than the token's. Check VARN_API_URL.");
  }
  const slug = response.organization.slug.toLowerCase();
  for (const ref of refs) {
    if (ref.org !== slug) {
      throw new CliError(
        EXIT.wrongOrganization,
        `${ref.raw}: the reference is for organisation "${ref.org}", but the token belongs to "${response.organization.slug}".`,
      );
    }
  }

  const expiresAt = Date.parse(response.machine.expires_at);
  const days = opts.expiryWarningDays ?? 14;
  const now = (opts.now ?? (() => new Date()))().getTime();
  if (Number.isFinite(expiresAt) && expiresAt - now < days * 86_400_000) {
    opts.warn(`This machine account expires on ${new Date(expiresAt).toISOString().slice(0, 10)}. Create a new one in Värn and replace the token before then.`);
  }

  let machine: UnlockedMachine;
  try {
    machine = await unlockMachine(token, response.machine.public_key);
  } catch {
    throw new CliError(EXIT.decrypt, "The machine's public key from the API does not belong to this token.");
  }

  const vault = new Vault(response, machine, opts.warn);
  const resolved: ResolvedSecret[] = [];
  for (const ref of refs) resolved.push(await vault.resolve(ref));
  return resolved;
}
