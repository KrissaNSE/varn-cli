/**
 * The CLI end to end, in-process: real fixtures made with the shared crypto,
 * served by a local HTTP server, read/inject/run with real child processes.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { EventEmitter } from "node:events";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { MACHINE_API_ERRORS, MACHINE_API_STATUS } from "../../../src/domain/vault/machine-api";
import { EXIT } from "../src/errors";
import { MASK } from "../src/mask";
import { VERSION } from "../src/version";
import { VALUES, buildFixture, runCli, startApi, type ApiServer, type CliRun, type Fixture } from "./fixtures";

let fx: Fixture;
let api: ApiServer;
let dir: string;
let env: Record<string, string>;

beforeAll(async () => {
  fx = await buildFixture();
  api = await startApi(fx);
  dir = await mkdtemp(path.join(tmpdir(), "varn-cli-"));
});

afterAll(async () => {
  await api.close();
  await rm(dir, { recursive: true, force: true });
});

beforeEach(() => {
  api.reset();
  env = { ...baseEnv(), VARN_TOKEN: fx.token, VARN_API_URL: api.url };
});

/** The test process's environment (child processes on Windows need e.g. SYSTEMROOT), without VARN_*. */
function baseEnv(): Record<string, string> {
  return Object.fromEntries(Object.entries(process.env).filter((e): e is [string, string] => e[1] !== undefined && !e[0].startsWith("VARN_")));
}

const ref = (collection: string, item: string, field = "password") => `varn://exempel/${collection}/${item}/${field}`;

/** Nothing secret may appear in what varn itself prints on stderr. */
function expectNoSecretsIn(text: string) {
  expect(text).not.toContain(fx.token);
  expect(text).not.toContain(fx.token.slice(8, 40));
  expect(text).not.toContain(fx.bearer);
  for (const value of Object.values(VALUES)) expect(text).not.toContain(value);
}

describe("varn read", () => {
  it("resolves a reference by names, case-insensitively, and prints the exact value", async () => {
    const r = await runCli(["read", ref("produktion", "PRODUKTIONSDATABAS")], { env });
    expect(r).toMatchObject({ exitCode: 0, stdout: VALUES.dbPassword });
    expectNoSecretsIn(r.stderr);
    // Names are resolved locally: the whole held set is fetched, no names are sent.
    expect(api.requests).toHaveLength(1);
    expect(api.requests[0]!.url).toBe("/api/vault/v1/collections");
    expect(api.requests[0]!.authorization).toBe(`Bearer ${fx.bearer}`);
    expect(api.requests[0]!.userAgent).toBe(`varn-cli/${VERSION}`);
  });

  it("adds a newline only when stdout is a terminal", async () => {
    expect((await runCli(["read", ref("Produktion", "Stripe")], { env, tty: true })).stdout).toBe(`${VALUES.stripe}\n`);
  });

  it("reads every field, including multi-line notes", async () => {
    expect((await runCli(["read", ref("Produktion", "Produktionsdatabas", "username")], { env })).stdout).toBe(VALUES.dbUser);
    expect((await runCli(["read", ref("Produktion", "Produktionsdatabas", "notes")], { env })).stdout).toBe(VALUES.notes);
  });

  it("fetches only the referenced collection when the reference uses ids", async () => {
    const r = await runCli(["read", `varn://exempel/id:${fx.ids.prod}/id:${fx.ids.stripe}/password`], { env });
    expect(r).toMatchObject({ exitCode: 0, stdout: VALUES.stripe });
    expect(api.requests[0]!.url).toBe(`/api/vault/v1/collections?ids=${fx.ids.prod}`);
  });

  it("mixes ids and names", async () => {
    expect((await runCli(["read", `varn://exempel/id:${fx.ids.prod}/Stripe/password`], { env })).stdout).toBe(VALUES.stripe);
    expect((await runCli(["read", `varn://exempel/Produktion/id:${fx.ids.stripe}/password`], { env })).stdout).toBe(VALUES.stripe);
  });

  it("decodes URL-encoded names and tells an encoded id: apart from an id", async () => {
    expect((await runCli(["read", ref("Produktion", "med%20mellanslag%2Foch%20snedstreck")], { env })).stdout).toBe(VALUES.spaced);
    expect((await runCli(["read", ref("Produktion", "id%3Ainte-ett-id")], { env })).stdout).toBe("named-like-an-id");
  });

  it("reads items under the old and the new key during a rotation", async () => {
    expect((await runCli(["read", ref("Test", "Gammal")], { env })).stdout).toBe(VALUES.oldKey);
    expect((await runCli(["read", ref("Test", "Ny")], { env })).stdout).toBe(VALUES.newKey);
  });

  it("skips a collection whose grant does not open, with a warning", async () => {
    const r = await runCli(["read", ref("Produktion", "Stripe")], { env });
    expect(r.exitCode).toBe(0);
    // The broken collection is only decrypted when names must be matched, and then warned about.
    expect(r.stderr).toBe(`varn: warning: Collection ${fx.ids.broken} could not be decrypted with this machine's grant; it is skipped.\n`);
    const missing = await runCli(["read", ref("Trasig", "X")], { env });
    expect(missing.exitCode).toBe(EXIT.notFound);
    expect(missing.stderr).toContain("1 collection(s) could not be decrypted");
    const byId = await runCli(["read", `varn://exempel/id:${fx.ids.broken}/X/password`], { env });
    expect(byId.exitCode).toBe(EXIT.notFound);
  });

  it("prints the item version and update time with --verbose", async () => {
    const r = await runCli(["--verbose", "read", ref("Produktion", "Stripe")], { env });
    expect(r.stderr).toContain(`→ item ${fx.ids.stripe} version 2, updated `);
  });

  it("refuses an ambiguous item or collection name and names the ids", async () => {
    const item = await runCli(["read", ref("Produktion", "API-NYCKEL")], { env });
    expect(item.exitCode).toBe(EXIT.ambiguous);
    expect(item.stderr).toContain("2 items in the collection are named");
    expect(item.stdout).toBe("");
    const collection = await runCli(["read", ref("dubbel", "x")], { env });
    expect(collection.exitCode).toBe(EXIT.ambiguous);
    expect(collection.stderr).toContain(fx.ids.dubbel1);
    expect(collection.stderr).toContain(fx.ids.dubbel2);
    expectNoSecretsIn(item.stderr + collection.stderr);
  });

  it("reports missing collections, items and empty fields", async () => {
    expect((await runCli(["read", ref("Ekonomi", "Bank")], { env })).exitCode).toBe(EXIT.notFound);
    expect((await runCli(["read", ref("Produktion", "Finns%20inte")], { env })).exitCode).toBe(EXIT.notFound);
    expect((await runCli(["read", `varn://exempel/id:${fx.ids.prod}/id:${fx.ids.oldItem}/password`], { env })).exitCode).toBe(EXIT.notFound);
    const empty = await runCli(["read", ref("Produktion", "Produktionsdatabas", "url")], { env });
    expect(empty.exitCode).toBe(EXIT.notFound);
    expect(empty.stderr).toContain("url is empty");
  });

  it("refuses a reference to another organisation than the token's", async () => {
    const r = await runCli(["read", "varn://annan/Produktion/Stripe/password"], { env });
    expect(r.exitCode).toBe(EXIT.wrongOrganization);
    expect(r.stderr).toContain('token belongs to "exempel"');
    expect(r.stdout).toBe("");
  });

  it("refuses a response for another organisation or machine", async () => {
    api.reply = () => ({ status: 200, body: { ...fx.response, organization: { id: crypto.randomUUID(), slug: "exempel" } } });
    expect((await runCli(["read", ref("Produktion", "Stripe")], { env })).exitCode).toBe(EXIT.decrypt);
    api.reply = () => ({ status: 200, body: { ...fx.response, machine: { ...fx.response.machine, id: crypto.randomUUID() } } });
    expect((await runCli(["read", ref("Produktion", "Stripe")], { env })).exitCode).toBe(EXIT.decrypt);
  });

  it("refuses a machine public key that does not belong to the token", async () => {
    const other = await buildFixture();
    api.reply = () => ({ status: 200, body: { ...fx.response, machine: { ...fx.response.machine, public_key: other.response.machine.public_key } } });
    const r = await runCli(["read", ref("Produktion", "Stripe")], { env });
    expect(r.exitCode).toBe(EXIT.decrypt);
    expect(r.stdout).toBe("");
  });

  it("warns when the machine account expires within 14 days", async () => {
    api.reply = () => ({ status: 200, body: { ...fx.response, machine: { ...fx.response.machine, expires_at: new Date(Date.now() + 3 * 86_400_000).toISOString() } } });
    const r = await runCli(["read", `varn://exempel/id:${fx.ids.prod}/Stripe/password`], { env });
    expect(r.exitCode).toBe(0);
    expect(r.stderr).toContain("This machine account expires on");
  });

  it("refuses a bad reference before calling the API", async () => {
    const r = await runCli(["read", "varn://exempel/Produktion/Stripe/secret"], { env });
    expect(r.exitCode).toBe(EXIT.badReference);
    expect(api.requests).toHaveLength(0);
  });
});

describe("token and configuration", () => {
  it("needs a token", async () => {
    const r = await runCli(["read", ref("Produktion", "Stripe")], { env: { VARN_API_URL: api.url } });
    expect(r.exitCode).toBe(EXIT.token);
    expect(r.stderr).toContain("No machine token");
  });

  it("refuses a malformed token without echoing it", async () => {
    const broken = fx.token.slice(0, -2) + (fx.token.endsWith("00") ? "22" : "00");
    const r = await runCli(["read", ref("Produktion", "Stripe")], { env: { ...env, VARN_TOKEN: broken } });
    expect(r.exitCode).toBe(EXIT.token);
    expect(r.stderr).not.toContain(broken.slice(8, 30));
    expect(api.requests).toHaveLength(0);
  });

  it("reads --token-file, also the file Värn offers for download", async () => {
    const file = path.join(dir, "token.txt");
    await writeFile(file, `Värn-maskintoken för CI\n\n${fx.token}\n\nOrganisation: exempel\nGiltig till: 2027-01-28\n`, { mode: 0o600 });
    const r = await runCli(["read", "--token-file", file, ref("Produktion", "Stripe")], { env: { VARN_API_URL: api.url } });
    expect(r).toMatchObject({ exitCode: 0, stdout: VALUES.stripe });
    // --token-file wins over VARN_TOKEN, and works before the command too.
    const before = await runCli([`--token-file=${file}`, "read", ref("Produktion", "Stripe")], { env: { ...env, VARN_TOKEN: "varn_mt_wrong" } });
    expect(before.exitCode).toBe(0);
    expect((await runCli(["read", "--token-file", path.join(dir, "missing"), ref("Produktion", "Stripe")], { env })).exitCode).toBe(EXIT.token);
  });

  it.skipIf(process.platform === "win32")("warns when the token file is readable by others", async () => {
    const file = path.join(dir, "open-token.txt");
    await writeFile(file, fx.token, { mode: 0o644 });
    const r = await runCli(["read", "--token-file", file, ref("Produktion", "Stripe")], { env: { VARN_API_URL: api.url } });
    expect(r.exitCode).toBe(0);
    expect(r.stderr).toContain("chmod 600");
  });

  it.each([
    ["http://example.com", EXIT.config],
    ["http://varnsecurity.se.evil.example", EXIT.config],
    ["ftp://localhost", EXIT.config],
    ["not a url", EXIT.config],
    ["https://user:pw@www.varnsecurity.se", EXIT.config],
  ])("refuses VARN_API_URL=%s", async (url, code) => {
    const r = await runCli(["read", ref("Produktion", "Stripe")], { env: { ...env, VARN_API_URL: url } });
    expect(r.exitCode).toBe(code);
    expect(api.requests).toHaveLength(0);
  });

  it("allows plain http for localhost", async () => {
    const port = new URL(api.url).port;
    expect((await runCli(["read", ref("Produktion", "Stripe")], { env: { ...env, VARN_API_URL: `http://localhost:${port}` } })).exitCode).toBe(0);
  });
});

describe("API errors", () => {
  const cases = MACHINE_API_ERRORS.map((code) => [code, MACHINE_API_STATUS[code]] as const);
  const expected: Record<(typeof MACHINE_API_ERRORS)[number], number> = {
    invalid_request: EXIT.server,
    unauthorized: EXIT.unauthorized,
    not_entitled: EXIT.notEntitled,
    collection_not_found: EXIT.notFound,
    rate_limited: EXIT.rateLimited,
    vault_disabled: EXIT.vaultDisabled,
    server_error: EXIT.server,
  };

  it.each(cases)("maps %s (%i) to its own exit code and message", async (code, status) => {
    api.reply = () => ({
      status,
      headers: code === "rate_limited" ? { "retry-after": "60" } : ({} as Record<string, string>),
      body: { api_version: 1, error: code, ...(code === "collection_not_found" ? { collection_ids: [fx.ids.prod] } : {}) },
    });
    const r = await runCli(["read", ref("Produktion", "Stripe")], { env });
    expect(r.exitCode).toBe(expected[code]);
    expect(r.stderr).toContain(code);
    expect(r.stdout).toBe("");
    if (code === "rate_limited") expect(r.stderr).toContain("retry after 60 seconds");
    if (code === "collection_not_found") expect(r.stderr).toContain(fx.ids.prod);
    expectNoSecretsIn(r.stderr);
  });

  it("gives every error its own exit code", () => {
    const codes = Object.values(EXIT);
    expect(new Set(codes).size).toBe(codes.length);
  });

  it("reports the real API's 404 for an id the machine cannot read", async () => {
    const id = crypto.randomUUID();
    const r = await runCli(["read", `varn://exempel/id:${id}/Stripe/password`], { env });
    expect(r.exitCode).toBe(EXIT.notFound);
    expect(r.stderr).toContain(id);
  });

  it("reports a wrong token as 401", async () => {
    const other = await buildFixture();
    const r = await runCli(["read", ref("Produktion", "Stripe")], { env: { ...env, VARN_TOKEN: other.token } });
    expect(r.exitCode).toBe(EXIT.unauthorized);
    expectNoSecretsIn(r.stderr);
    expect(r.stderr).not.toContain(other.token);
  });

  it("handles the edge's 429 without a JSON body, and unknown statuses", async () => {
    api.reply = () => ({ status: 429, body: "Too Many Requests" });
    expect((await runCli(["read", ref("Produktion", "Stripe")], { env })).exitCode).toBe(EXIT.rateLimited);
    api.reply = () => ({ status: 502, body: "Bad gateway" });
    expect((await runCli(["read", ref("Produktion", "Stripe")], { env })).exitCode).toBe(EXIT.server);
  });

  it("refuses a 200 that is not the v1 contract", async () => {
    api.reply = () => ({ status: 200, body: { api_version: 2, collections: [] } });
    expect((await runCli(["read", ref("Produktion", "Stripe")], { env })).exitCode).toBe(EXIT.network);
    api.reply = () => ({ status: 200, body: "<html>" });
    expect((await runCli(["read", ref("Produktion", "Stripe")], { env })).exitCode).toBe(EXIT.network);
  });

  it("does not follow redirects with the bearer value", async () => {
    api.reply = () => ({ status: 301, headers: { location: "https://elsewhere.example/api/vault/v1/collections" } });
    const r = await runCli(["read", ref("Produktion", "Stripe")], { env });
    expect(r.exitCode).toBe(EXIT.network);
    expect(r.stderr).toContain("redirect to https://elsewhere.example");
    expect(api.requests).toHaveLength(1);
  });

  it("reports an unreachable API", async () => {
    const r = await runCli(["read", ref("Produktion", "Stripe")], { env: { ...env, VARN_API_URL: "http://127.0.0.1:1" } });
    expect(r.exitCode).toBe(EXIT.network);
    expect(r.stderr).toContain("Could not reach the API");
  });
});

describe("varn inject", () => {
  const template = () =>
    [
      "database:",
      `  user: {{ ${ref("Produktion", "Produktionsdatabas", "username")} }}`,
      `  password: "{{${ref("Produktion", "Produktionsdatabas")}}}"`,
      `stripe: {{ varn://exempel/id:${fx.ids.prod}/Stripe/password }}`,
      `again: {{ ${ref("Produktion", "Stripe")} }}`,
      "literal: { not: a placeholder }",
      "",
    ].join("\n");
  const expectedOutput = () =>
    ["database:", `  user: ${VALUES.dbUser}`, `  password: "${VALUES.dbPassword}"`, `stripe: ${VALUES.stripe}`, `again: ${VALUES.stripe}`, "literal: { not: a placeholder }", ""].join("\n");

  it("fills placeholders from a template file to stdout, with one API request", async () => {
    const file = path.join(dir, "config.tpl");
    await writeFile(file, template());
    const r = await runCli(["inject", "-i", file], { env });
    expect(r).toMatchObject({ exitCode: 0, stdout: expectedOutput() });
    expect(api.requests).toHaveLength(1);
  });

  it("reads the template from stdin", async () => {
    expect((await runCli(["inject"], { env, stdin: template() })).stdout).toBe(expectedOutput());
  });

  it("writes -o with mode 0600, replacing an existing file", async () => {
    const out = path.join(dir, "config.yml");
    await writeFile(out, "old", { mode: 0o644 });
    const r = await runCli(["inject", "--in", "-", "--out", out], { env, stdin: template() });
    expect(r).toMatchObject({ exitCode: 0, stdout: "" });
    expect(await readFile(out, "utf8")).toBe(expectedOutput());
    if (process.platform !== "win32") expect((await stat(out)).mode & 0o777).toBe(0o600);
  });

  it("writes nothing when a reference fails", async () => {
    const out = path.join(dir, "not-written.yml");
    const r = await runCli(["inject", "-o", out], { env, stdin: `a: {{ ${ref("Produktion", "Finns%20inte")} }}` });
    expect(r.exitCode).toBe(EXIT.notFound);
    await expect(stat(out)).rejects.toThrow();
  });

  it("refuses a malformed placeholder reference, and a missing template", async () => {
    expect((await runCli(["inject"], { env, stdin: "{{ varn://exempel/x/password }}" })).exitCode).toBe(EXIT.badReference);
    const spaced = await runCli(["inject"], { env, stdin: "{{ varn://exempel/Produktion/Finns inte/password }}" });
    expect(spaced.exitCode).toBe(EXIT.badReference);
    expect(spaced.stderr).toContain("%20");
    expect((await runCli(["inject", "-i", path.join(dir, "nope.tpl")], { env })).exitCode).toBe(EXIT.io);
  });

  it("passes a template without placeholders through, without a token", async () => {
    const r = await runCli(["inject"], { env: {}, stdin: "plain\n" });
    expect(r).toMatchObject({ exitCode: 0, stdout: "plain\n" });
    expect(r.stderr).toContain("no {{ varn://… }} placeholders");
  });
});

describe("varn run", () => {
  const node = process.execPath;
  const hex = (s: string) => Buffer.from(s, "utf8").toString("hex");

  it("resolves references in the environment and hides VARN_TOKEN from the command", async () => {
    const r = await runCli(
      ["run", "--", node, "-e", "const h=(s)=>s===undefined?null:Buffer.from(s).toString('hex');console.log(JSON.stringify({db:h(process.env.DB),user:h(process.env.DB_USER),plain:process.env.PLAIN,token:process.env.VARN_TOKEN??null}))"],
      { env: { ...env, DB: ref("Produktion", "Produktionsdatabas"), DB_USER: ref("Produktion", "Produktionsdatabas", "username"), PLAIN: "plain" } },
    );
    expect(r.exitCode).toBe(0);
    expect(JSON.parse(r.stdout)).toEqual({ db: hex(VALUES.dbPassword), user: hex(VALUES.dbUser), plain: "plain", token: null });
  });

  it("masks values printed on stdout and stderr, also when written in pieces", async () => {
    const script = [
      "const v=process.env.DB;",
      "process.stdout.write('pw='+v.slice(0,4));",
      "setTimeout(()=>{process.stdout.write(v.slice(4)+'\\n');process.stderr.write('err '+process.env.USER_NAME+' done\\n');},30);",
    ].join("");
    const r = await runCli(["run", "--", node, "-e", script], {
      env: { ...env, DB: ref("Produktion", "Produktionsdatabas"), USER_NAME: ref("Produktion", "Produktionsdatabas", "username") },
    });
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toBe(`pw=${MASK}\n`);
    expect(r.stderr).toContain(`err ${MASK} done\n`);
    expectNoSecretsIn(r.stdout + r.stderr);
  });

  it("does not mask with --no-masking", async () => {
    const r = await runCli(["run", "--no-masking", "--", node, "-e", "process.stdout.write(process.env.DB)"], { env: { ...env, DB: ref("Produktion", "Stripe") } });
    expect(r.stdout).toBe(VALUES.stripe);
  });

  it("reads --env-file, which overrides the environment", async () => {
    const file = path.join(dir, "app.env");
    await writeFile(file, `# app\nSTRIPE_KEY=${ref("Produktion", "Stripe")}\nMODE=from-file\n`);
    const r = await runCli(
      ["run", "--env-file", file, "--", node, "-e", "console.log(Buffer.from(process.env.STRIPE_KEY).toString('hex'), process.env.MODE)"],
      { env: { ...env, MODE: "from-env" } },
    );
    expect(r.exitCode).toBe(0);
    expect(r.stdout.trim()).toBe(`${hex(VALUES.stripe)} from-file`);
  });

  it("passes the command's exit code through", async () => {
    expect((await runCli(["run", "--", node, "-e", "process.exit(42)"], { env: { ...env, DB: ref("Produktion", "Stripe") } })).exitCode).toBe(42);
  });

  it("runs the command unchanged, without a token, when nothing is a reference", async () => {
    const r = await runCli(["run", "--", node, "-e", "process.exit(0)"], { env: { ...baseEnv(), PLAIN: "x" } });
    expect(r.exitCode).toBe(0);
    expect(r.stderr).toContain("no environment variable holds a varn:// reference");
  });

  it("does not start the command when a reference fails, naming the variable", async () => {
    const marker = path.join(dir, "started");
    const r = await runCli(["run", "--", node, "-e", `require('fs').writeFileSync(${JSON.stringify(marker)}, '')`], {
      env: { ...env, BAD: "varn://exempel/Produktion/Stripe/pin" },
    });
    expect(r.exitCode).toBe(EXIT.badReference);
    expect(r.stderr).toContain("BAD: Invalid reference");
    await expect(stat(marker)).rejects.toThrow();
  });

  it("reports a command that does not exist", async () => {
    const r = await runCli(["run", "--", path.join(dir, "no-such-command.exe")], { env: { ...env, DB: ref("Produktion", "Stripe") } });
    expect(r.exitCode).toBe(EXIT.commandNotFound);
  });

  it("forwards signals to the command and reports how it ended", async () => {
    const signals = new EventEmitter();
    const pending = runCli(["run", "--", node, "-e", "console.log('ready'); setInterval(() => {}, 1000)"], { env: { ...env, DB: ref("Produktion", "Stripe") }, signals });
    // Wait until a listener is installed and the child has started.
    await new Promise((resolve) => setTimeout(resolve, 500));
    expect(signals.listenerCount("SIGINT")).toBe(1);
    signals.emit("SIGINT");
    const r: CliRun = await pending;
    expect(r.signal).toBe("SIGINT");
    expect(r.exitCode).toBe(130);
    expect(signals.listenerCount("SIGINT")).toBe(0);
  });

  it("needs a command", async () => {
    expect((await runCli(["run"], { env })).exitCode).toBe(EXIT.usage);
    expect((await runCli(["run", "--no-masking", "--"], { env })).exitCode).toBe(EXIT.usage);
  });
});

describe("usage", () => {
  it("prints the version and help", async () => {
    expect((await runCli(["--version"])).stdout).toBe(`${VERSION}\n`);
    expect((await runCli(["version"])).stdout).toBe(`${VERSION}\n`);
    expect((await runCli(["help"])).stdout).toContain("varn run [options] -- <command>");
    expect((await runCli(["help", "inject"])).stdout).toContain("0600");
    expect((await runCli(["run", "--help"])).stdout).toContain("--no-masking");
  });

  it("refuses unknown commands and options", async () => {
    expect((await runCli([])).exitCode).toBe(EXIT.usage);
    expect((await runCli(["fetch"])).exitCode).toBe(EXIT.usage);
    expect((await runCli(["read", "--nope", "x"])).exitCode).toBe(EXIT.usage);
    expect((await runCli(["read"])).exitCode).toBe(EXIT.usage);
    expect((await runCli(["read", "a", "b"])).exitCode).toBe(EXIT.usage);
    expect((await runCli(["inject", "-i"])).exitCode).toBe(EXIT.usage);
    expect((await runCli(["read", "--verbose=yes", "x"])).exitCode).toBe(EXIT.usage);
  });
});
