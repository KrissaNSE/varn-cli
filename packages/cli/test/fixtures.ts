/**
 * Test fixtures for the CLI, made with the same crypto the web app uses: an
 * organisation, a member who grants, collection keys, encrypted names and
 * items, a machine account with grants, and the read API's JSON for it,
 * served from a local HTTP server.
 */
import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { PassThrough, Readable } from "node:stream";
import { randomUUID } from "node:crypto";
import { EventEmitter } from "node:events";
import {
  createMachineAccount,
  encryptCollectionName,
  encryptItem,
  generateCollectionKey,
  machineBearer,
  parseMachineToken,
  toBase64,
  wrapCollectionKeyForMachine,
  type MachineWrap,
  type UnlockedIdentity,
} from "../../../src/domain/vault/crypto";
import type { MachineCollection, MachineReadResponse } from "../../../src/domain/vault/machine-api";
import { emptyItem, type VaultItemPayload } from "../../../src/domain/vault/model";
import { main, type CliIO } from "../src/main";
import type { RunResult } from "../src/run";

async function identity(orgId: string, userId: string): Promise<UnlockedIdentity> {
  const pair = (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])) as CryptoKeyPair;
  return { orgId, userId, publicKey: pair.publicKey, publicKeyB64: toBase64(await crypto.subtle.exportKey("raw", pair.publicKey)), privateKey: pair.privateKey };
}

const item = (fields: Partial<VaultItemPayload> & { name: string }): VaultItemPayload => ({ ...emptyItem(), ...fields });

export const VALUES = {
  dbPassword: "s3cret-db-pässwörd!",
  dbUser: "app_user",
  stripe: "sk_live_51HxExample",
  api1: "api-key-one",
  api2: "api-key-two",
  spaced: "value with spaces",
  oldKey: "rotated-old-key-value",
  newKey: "rotated-new-key-value",
  notes: "line one\nline two",
} as const;

export interface Fixture {
  orgId: string;
  slug: string;
  token: string;
  bearer: string;
  machineId: string;
  ids: {
    prod: string;
    test: string;
    dubbel1: string;
    dubbel2: string;
    broken: string;
    db: string;
    stripe: string;
    oldItem: string;
  };
  /** The API response with every collection the machine holds. */
  response: MachineReadResponse;
}

export async function buildFixture(opts: { expiresAt?: string } = {}): Promise<Fixture> {
  const orgId = randomUUID();
  const alice = await identity(orgId, randomUUID());
  const ids = {
    prod: randomUUID(),
    test: randomUUID(),
    dubbel1: randomUUID(),
    dubbel2: randomUUID(),
    broken: randomUUID(),
    db: randomUUID(),
    stripe: randomUUID(),
    oldItem: randomUUID(),
  };
  const prodKey = await generateCollectionKey();
  const account = await createMachineAccount({ orgId, sender: alice, collections: [{ collectionId: ids.prod, keyVersion: 1, key: prodKey }] });
  const ctx = { orgId, machineId: account.machineId };
  const grantJson = (w: MachineWrap) => ({
    key_version: w.keyVersion,
    ephemeral_public_key: w.grant.ephemeralPublicKey,
    iv: w.grant.iv,
    wrapped_key: w.grant.wrappedKey,
    sender_user_id: alice.userId,
    sender_public_key: alice.publicKeyB64,
  });
  const now = new Date().toISOString();

  async function collection(
    id: string,
    name: string,
    keys: Map<number, CryptoKey>,
    grants: MachineWrap[],
    items: { id?: string; keyVersion: number; payload: VaultItemPayload }[],
  ): Promise<MachineCollection> {
    const current = Math.max(...keys.keys());
    const encName = await encryptCollectionName(keys.get(current)!, { orgId, collectionId: id, version: 1, keyVersion: current }, name);
    return {
      id,
      key_version: current,
      name: { version: 1, ...encName },
      grants: grants.map(grantJson),
      items: await Promise.all(
        items.map(async (it) => {
          const itemId = it.id ?? randomUUID();
          const enc = await encryptItem(keys.get(it.keyVersion)!, { orgId, collectionId: id, itemId, version: 2, keyVersion: it.keyVersion }, it.payload);
          return { id: itemId, version: 2, key_version: it.keyVersion, ...enc, has_file: false, created_at: now, updated_at: now };
        }),
      ),
    };
  }

  const wrapFor = (collectionId: string, keyVersion: number, key: CryptoKey) =>
    wrapCollectionKeyForMachine({ ctx, collection: { collectionId, keyVersion, key }, sender: alice, machinePublicKey: account.publicKey });

  // Produktion: the main collection.
  const prod = await collection(ids.prod, "Produktion", new Map([[1, prodKey]]), account.grants, [
    { id: ids.db, keyVersion: 1, payload: item({ name: "Produktionsdatabas", username: VALUES.dbUser, password: VALUES.dbPassword, url: "", notes: VALUES.notes }) },
    { id: ids.stripe, keyVersion: 1, payload: item({ name: "Stripe", password: VALUES.stripe }) },
    { keyVersion: 1, payload: item({ name: "API-nyckel", password: VALUES.api1 }) },
    { keyVersion: 1, payload: item({ name: "api-nyckel", password: VALUES.api2 }) },
    { keyVersion: 1, payload: item({ name: "Med mellanslag/och snedstreck", password: VALUES.spaced }) },
    { keyVersion: 1, payload: item({ name: "id:inte-ett-id", password: "named-like-an-id" }) },
  ]);

  // Test: in the middle of a rotation (grants for key versions 1 and 2; one item still on version 1).
  const testV1 = await generateCollectionKey();
  const testV2 = await generateCollectionKey();
  const test = await collection(ids.test, "Test", new Map([[1, testV1], [2, testV2]]), [await wrapFor(ids.test, 1, testV1), await wrapFor(ids.test, 2, testV2)], [
    { id: ids.oldItem, keyVersion: 1, payload: item({ name: "Gammal", password: VALUES.oldKey }) },
    { keyVersion: 2, payload: item({ name: "Ny", password: VALUES.newKey }) },
  ]);

  // Two collections with the same name.
  const d1Key = await generateCollectionKey();
  const d2Key = await generateCollectionKey();
  const dubbel1 = await collection(ids.dubbel1, "Dubbel", new Map([[1, d1Key]]), [await wrapFor(ids.dubbel1, 1, d1Key)], []);
  const dubbel2 = await collection(ids.dubbel2, "DUBBEL", new Map([[1, d2Key]]), [await wrapFor(ids.dubbel2, 1, d2Key)], []);

  // A collection whose grant does not open (wrapped for another machine's key).
  const brokenKey = await generateCollectionKey();
  const other = await createMachineAccount({ orgId, sender: alice, collections: [{ collectionId: ids.broken, keyVersion: 1, key: brokenKey }] });
  const broken = await collection(ids.broken, "Trasig", new Map([[1, brokenKey]]), other.grants, [{ keyVersion: 1, payload: item({ name: "X", password: "x" }) }]);

  const response: MachineReadResponse = {
    api_version: 1,
    organization: { id: orgId, slug: "exempel" },
    machine: { id: account.machineId, public_key: account.publicKey, expires_at: opts.expiresAt ?? new Date(Date.now() + 90 * 86_400_000).toISOString() },
    collections: [prod, test, dubbel1, dubbel2, broken],
  };
  return { orgId, slug: "exempel", token: account.token, bearer: await machineBearer(await parseMachineToken(account.token)), machineId: account.machineId, ids, response };
}

export interface Reply {
  status: number;
  headers?: Record<string, string>;
  body?: unknown;
}

export interface ApiServer {
  url: string;
  requests: { url: string; authorization: string | undefined; userAgent: string | undefined }[];
  /** Overrides the next replies; reset() restores the fixture behaviour. */
  reply: ((req: IncomingMessage) => Reply) | null;
  reset(): void;
  close(): Promise<void>;
}

/** A local read API: answers like the real one for the fixture's bearer value. */
export async function startApi(fixture: Fixture): Promise<ApiServer> {
  const api: ApiServer = {
    url: "",
    requests: [],
    reply: null,
    reset() {
      this.reply = null;
      this.requests.length = 0;
    },
    close: () => new Promise<void>((resolve) => {
      server.closeAllConnections();
      server.close(() => resolve());
    }),
  };
  const standard = (req: IncomingMessage): Reply => {
    const url = new URL(req.url ?? "/", "http://localhost");
    if (url.pathname !== "/api/vault/v1/collections") return { status: 404, body: "not found" };
    if (req.headers.authorization !== `Bearer ${fixture.bearer}`) return { status: 401, body: { api_version: 1, error: "unauthorized" } };
    const idsParam = url.searchParams.get("ids");
    if (!idsParam) return { status: 200, body: fixture.response };
    const ids = idsParam.split(",");
    const missing = ids.filter((id) => !fixture.response.collections.some((c) => c.id === id));
    if (missing.length) return { status: 404, body: { api_version: 1, error: "collection_not_found", collection_ids: missing } };
    return { status: 200, body: { ...fixture.response, collections: fixture.response.collections.filter((c) => ids.includes(c.id)) } };
  };
  const server: Server = createServer((req, res) => {
    api.requests.push({ url: req.url ?? "", authorization: req.headers.authorization, userAgent: req.headers["user-agent"] });
    const r = (api.reply ?? standard)(req);
    const text = typeof r.body === "string" ? r.body : JSON.stringify(r.body ?? {});
    res.writeHead(r.status, { "content-type": typeof r.body === "string" ? "text/plain" : "application/json", ...r.headers });
    res.end(text);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  api.url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return api;
}

export interface CliRun extends RunResult {
  stdout: string;
  stderr: string;
}

/** Runs the CLI in-process with captured output. */
export async function runCli(
  argv: string[],
  opts: { env?: Record<string, string | undefined>; stdin?: string; tty?: boolean; cwd?: string; signals?: EventEmitter; platform?: NodeJS.Platform } = {},
): Promise<CliRun> {
  const stdout = Object.assign(new PassThrough(), { isTTY: opts.tty ?? false });
  const stderr = new PassThrough();
  const out: Buffer[] = [];
  const err: Buffer[] = [];
  stdout.on("data", (c: Buffer) => out.push(c));
  stderr.on("data", (c: Buffer) => err.push(c));
  const io: CliIO = {
    argv,
    env: opts.env ?? {},
    stdout,
    stderr,
    stdin: () => Readable.from([Buffer.from(opts.stdin ?? "")]),
    cwd: opts.cwd ?? process.cwd(),
    signals: opts.signals as CliIO["signals"],
    platform: opts.platform,
  };
  const result = await main(io);
  return { ...result, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8") };
}
