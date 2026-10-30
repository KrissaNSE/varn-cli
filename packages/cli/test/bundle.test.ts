/**
 * The published artefact: builds dist/varn.mjs into a temporary directory with
 * the same build as `npm run build:cli` and runs it as a real process.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { spawn, spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { buildCli } from "../scripts/build";
import pkg from "../package.json";
import { MASK } from "../src/mask";
import { VALUES, buildFixture, startApi, type ApiServer, type Fixture } from "./fixtures";

let dir: string;
let bin: string;
let fx: Fixture;
let api: ApiServer;

beforeAll(async () => {
  dir = await mkdtemp(path.join(tmpdir(), "varn-bundle-"));
  bin = await buildCli(dir);
  fx = await buildFixture();
  api = await startApi(fx);
}, 120_000);

afterAll(async () => {
  await api?.close();
  await rm(dir, { recursive: true, force: true });
});

const env = () => ({ ...process.env, VARN_TOKEN: fx.token, VARN_API_URL: api.url });

/** Runs the bundle asynchronously (the local API runs in this process, so spawnSync would deadlock). */
function varn(args: string[], extraEnv: Record<string, string> = {}): Promise<{ code: number | null; signal: NodeJS.Signals | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [bin, ...args], { env: { ...env(), ...extraEnv } });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (c: Buffer) => (stdout += c.toString()));
    child.stderr.on("data", (c: Buffer) => (stderr += c.toString()));
    child.on("close", (code, signal) => resolve({ code, signal, stdout, stderr }));
  });
}

describe("dist/varn.mjs", () => {
  it("is one ESM file with a shebang, no imports outside Node, and the package version", async () => {
    const source = await readFile(bin, "utf8");
    expect(source.startsWith("#!/usr/bin/env node\n")).toBe(true);
    const imports = [...source.matchAll(/^import .* from "([^"]+)";$/gm)].map((m) => m[1]);
    expect(imports.length).toBeGreaterThan(0);
    for (const specifier of imports) expect(specifier).toMatch(/^node:/);
    expect(source).not.toMatch(/\brequire\(/);
    const r = spawnSync(process.execPath, [bin, "--version"], { encoding: "utf8" });
    expect(r.status).toBe(0);
    expect(r.stdout).toBe(`${pkg.version}\n`);
  });

  it("declares no runtime dependencies", () => {
    expect((pkg as Record<string, unknown>).dependencies).toBeUndefined();
    expect(pkg.bin).toEqual({ varn: "dist/varn.mjs" });
  });

  it("reads a secret through the local API", async () => {
    const r = await varn(["read", "varn://exempel/Produktion/Stripe/password"]);
    expect(r.code).toBe(0);
    expect(r.stdout).toBe(VALUES.stripe);
  });

  it("runs a command with masking and passes its exit code through", async () => {
    const r = await varn(["run", "--", process.execPath, "-e", "console.log(process.env.KEY); process.exit(5)"], { KEY: "varn://exempel/Produktion/Stripe/password" });
    expect(r.code).toBe(5);
    expect(r.stdout.trim()).toBe(MASK);
  });

  it("exits with a distinct code on failure, without leaking the token", async () => {
    const r = await varn(["read", "varn://annan/Produktion/Stripe/password"]);
    expect(r.code).toBe(15);
    expect(r.stderr).not.toContain(fx.token);
    expect(r.stderr).not.toContain(fx.bearer);
  });

  it.skipIf(process.platform === "win32")("forwards SIGTERM to the command and ends with the same signal", async () => {
    const child = spawn(process.execPath, [bin, "run", "--", process.execPath, "-e", "console.log('ready'); setInterval(() => {}, 1000)"], {
      env: { ...env(), KEY: "varn://exempel/Produktion/Stripe/password" },
    });
    await new Promise<void>((resolve) => child.stdout.once("data", () => resolve()));
    child.kill("SIGTERM");
    const [code, signal] = await new Promise<[number | null, NodeJS.Signals | null]>((resolve) => child.on("close", (c, s) => resolve([c, s])));
    expect(code).toBeNull();
    expect(signal).toBe("SIGTERM");
  });
});
