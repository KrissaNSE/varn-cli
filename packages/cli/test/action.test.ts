/** The GitHub Action wrapper (packages/cli/action). */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import yaml from "js-yaml";
import pkg from "../package.json";

const ACTION_DIR = path.resolve(__dirname, "..", "action");
let dir: string;

beforeAll(async () => {
  dir = await mkdtemp(path.join(tmpdir(), "varn-action-"));
});
afterAll(async () => {
  await rm(dir, { recursive: true, force: true });
});

interface Action {
  inputs: Record<string, { required?: boolean; default?: string }>;
  runs: { using: string; steps: { run?: string; env?: Record<string, string> }[] };
}

describe("action.yml", () => {
  it("is a composite action whose default version is the package version", async () => {
    const action = yaml.load(await readFile(path.join(ACTION_DIR, "action.yml"), "utf8")) as Action;
    expect(action.runs.using).toBe("composite");
    expect(action.inputs.token!.required).toBe(true);
    expect(action.inputs.version!.default).toBe(pkg.version);
  });

  it("never expands an input inside a script (no shell injection)", async () => {
    const action = yaml.load(await readFile(path.join(ACTION_DIR, "action.yml"), "utf8")) as Action;
    for (const step of action.runs.steps) expect(step.run ?? "").not.toContain("${{");
  });
});

describe("export.mjs", () => {
  it("masks each value (whole and per line) and appends it to GITHUB_ENV with a safe delimiter", async () => {
    const envFile = path.join(dir, "export.env");
    const githubEnv = path.join(dir, "github_env");
    await writeFile(envFile, "# comment\nDB_PASSWORD=varn://exempel/Produktion/Databas/password\nexport KEY = varn://exempel/Produktion/Nyckel/notes\nEMPTY=\n");
    await writeFile(githubEnv, "");
    const r = spawnSync(process.execPath, [path.join(ACTION_DIR, "export.mjs"), envFile], {
      env: { ...process.env, GITHUB_ENV: githubEnv, DB_PASSWORD: "p%ss\rword", KEY: "-----BEGIN-----\nabc\n-----END-----", EMPTY: "" },
      encoding: "utf8",
    });
    expect(r.status).toBe(0);
    expect(r.stdout.split("\n").filter(Boolean)).toEqual([
      "::add-mask::p%25ss%0Dword",
      "::add-mask::-----BEGIN-----%0Aabc%0A-----END-----",
      "::add-mask::-----BEGIN-----",
      "::add-mask::abc",
      "::add-mask::-----END-----",
    ]);
    const written = await readFile(githubEnv, "utf8");
    expect(written).toMatch(/^DB_PASSWORD<<(VARN_[0-9a-f]{32})\np%ss\rword\n\1\nKEY<<(VARN_[0-9a-f]{32})\n-----BEGIN-----\nabc\n-----END-----\n\2\n$/);
  });
});
