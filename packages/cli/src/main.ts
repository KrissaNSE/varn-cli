/**
 * The `varn` command line: argument parsing and the commands read, run,
 * inject, help and --version. Everything the process touches (argv, env,
 * streams, fetch, signals) comes in through `CliIO` so the commands can be
 * tested in-process; ./bin.ts wires it to the real process.
 */
import { randomBytes } from "node:crypto";
import { chmod, readFile, rename, rm, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve as resolvePath } from "node:path";
import type { Readable, Writable } from "node:stream";
import { apiOrigin } from "./api";
import { readEnvFile } from "./env-file";
import { CliError, EXIT } from "./errors";
import { PLACEHOLDER, isReference, parseReference, type SecretReference } from "./reference";
import { resolveReferences, type ResolvedSecret } from "./resolve";
import { runCommand, type RunResult, type SignalSource } from "./run";
import { TOKEN_ENV, loadToken } from "./token";
import { VERSION } from "./version";

export interface CliIO {
  /** Arguments after `varn`. */
  argv: string[];
  env: Record<string, string | undefined>;
  stdout: Writable & { isTTY?: boolean };
  stderr: Writable;
  /** Only touched by `inject` without -i, so other commands never open stdin. */
  stdin: () => Readable;
  cwd: string;
  fetch?: typeof globalThis.fetch;
  signals?: SignalSource;
  platform?: NodeJS.Platform;
  now?: () => Date;
}

const HELP = {
  main: `varn ${VERSION} – use secrets from your Värn vault without putting them in code.

Usage:
  varn read <reference>                            Print one value
  varn run [options] -- <command> [args…]          Run a command with references in its environment resolved
  varn inject [-i <template>] [-o <file>]          Fill {{ varn://… }} placeholders in a template
  varn help [command]                              Show help
  varn --version                                   Show the version

A reference is varn://<organisation>/<collection>/<item>/<field>
  <collection> and <item> are names (case-insensitive, URL-encoded: a space is %20) or id:<uuid>
  <field> is password, username, url or notes

Options for every command:
  --token-file <path>   Read the machine token from a file instead of ${TOKEN_ENV}
  --verbose             Print which item version each reference resolved to (on stderr)

Environment:
  ${TOKEN_ENV}            The machine account's token (Secure vault → Machine accounts in Värn)
  VARN_API_URL          Värn's address (default https://www.varnsecurity.se; must be https)

Docs: https://www.varnsecurity.se/docs/hemligheter-i-kod-och-ci
`,
  read: `Usage: varn read [--token-file <path>] <reference>

Prints the value of one reference on stdout. A newline is added only when
stdout is a terminal, so  $(varn read …)  gives the exact value.

Example:
  varn read varn://exempel/Produktion/Databas/password
`,
  run: `Usage: varn run [--no-masking] [--env-file <file>]… [--token-file <path>] -- <command> [args…]

Every environment variable whose value is a varn:// reference – from the
current environment, or from --env-file (which takes precedence; several files
are read in order) – is replaced by the secret's value, and <command> is
started with that environment. ${TOKEN_ENV} is not passed on to the command.

By default, any secret value the command prints on stdout or stderr is replaced
with <varn:concealed>. The command's stdout and stderr are then pipes, not a
terminal. --no-masking turns this off.

varn forwards signals to the command and exits with the command's exit code.

Example:
  DATABASE_PASSWORD=varn://exempel/Produktion/Databas/password varn run -- npm start
`,
  inject: `Usage: varn inject [-i <template>] [-o <file>] [--token-file <path>]

Reads a template (from -i, or stdin) and replaces every {{ varn://… }}
placeholder with the secret's value. With -o the result is written to <file>
with permissions 0600 (only you can read it), replacing the file atomically;
otherwise it goes to stdout.

Example:
  varn inject -i config.yml.tpl -o config.yml
`,
} as const;

type Spec = Record<string, { value: boolean; repeat?: boolean; alias?: string }>;

interface Parsed {
  options: Map<string, string[]>;
  positionals: string[];
  /** Arguments after `--` (or after the first positional, for `run`). */
  rest: string[];
}

const GLOBAL: Spec = { "--token-file": { value: true }, "--verbose": { value: false }, "--help": { value: false, alias: "-h" } };

function parseArgs(args: string[], spec: Spec, stopAtPositional: boolean): Parsed {
  const all: Spec = { ...GLOBAL, ...spec };
  const aliases = new Map(Object.entries(all).flatMap(([name, s]) => (s.alias ? [[s.alias, name] as const] : [])));
  const options = new Map<string, string[]>();
  const positionals: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (arg === "--") return { options, positionals, rest: args.slice(i + 1) };
    if (arg.startsWith("-") && arg !== "-") {
      const eq = arg.indexOf("=");
      const rawName = eq > 0 && arg.startsWith("--") ? arg.slice(0, eq) : arg;
      const name = aliases.get(rawName) ?? rawName;
      const option = all[name];
      if (!option) throw new CliError(EXIT.usage, `Unknown option ${rawName}. See: varn help`);
      let value = "";
      if (option.value) {
        if (eq > 0 && arg.startsWith("--")) value = arg.slice(eq + 1);
        else if (i + 1 < args.length) value = args[++i]!;
        else throw new CliError(EXIT.usage, `${rawName} needs a value.`);
      } else if (eq > 0 && arg.startsWith("--")) {
        throw new CliError(EXIT.usage, `${rawName} does not take a value.`);
      }
      const list = options.get(name) ?? [];
      if (list.length > 0 && !option.repeat && option.value) throw new CliError(EXIT.usage, `${rawName} may only be given once.`);
      options.set(name, [...list, value]);
      continue;
    }
    if (stopAtPositional) return { options, positionals, rest: args.slice(i) };
    positionals.push(arg);
  }
  return { options, positionals, rest: [] };
}

const one = (parsed: Parsed, name: string) => parsed.options.get(name)?.[0];
const flag = (parsed: Parsed, name: string) => parsed.options.has(name);

class Context {
  constructor(
    readonly io: CliIO,
    readonly parsed: Parsed,
  ) {}

  warn = (message: string) => {
    this.io.stderr.write(`varn: warning: ${message}\n`);
  };

  path(p: string): string {
    return resolvePath(this.io.cwd, p);
  }

  async resolve(refs: SecretReference[]): Promise<ResolvedSecret[]> {
    if (refs.length === 0) return [];
    const origin = apiOrigin(this.io.env.VARN_API_URL);
    const tokenFile = one(this.parsed, "--token-file");
    const token = await loadToken({ env: this.io.env, tokenFile: tokenFile === undefined ? undefined : this.path(tokenFile), warn: this.warn, platform: this.io.platform });
    try {
      const resolved = await resolveReferences(refs, { token, origin, fetch: this.io.fetch, warn: this.warn, now: this.io.now });
      if (flag(this.parsed, "--verbose")) {
        for (const r of resolved) {
          this.io.stderr.write(`varn: ${r.reference.raw} → item ${r.itemId} version ${r.itemVersion}, updated ${r.updatedAt} (collection ${r.collectionId})\n`);
        }
      }
      return resolved;
    } finally {
      token.secret.fill(0);
    }
  }
}

async function readStream(stream: Readable): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : (chunk as Buffer));
  return Buffer.concat(chunks).toString("utf8");
}

/** Writes `data` to `path` with mode 0600 via a temporary file in the same directory and a rename. */
async function writePrivateFile(path: string, data: string): Promise<void> {
  const tmp = join(dirname(path), `.${basename(path)}.varn-${randomBytes(6).toString("hex")}.tmp`);
  try {
    await writeFile(tmp, data, { mode: 0o600, flag: "wx" });
    await chmod(tmp, 0o600);
    await rename(tmp, path);
  } catch (error) {
    await rm(tmp, { force: true }).catch(() => undefined);
    const code = (error as NodeJS.ErrnoException).code;
    throw new CliError(EXIT.io, `Could not write ${path}${code ? ` (${code})` : ""}.`);
  }
}

async function cmdRead(ctx: Context): Promise<RunResult> {
  const { positionals } = ctx.parsed;
  if (positionals.length !== 1) throw new CliError(EXIT.usage, "Usage: varn read <reference>");
  const [secret] = await ctx.resolve([parseReference(positionals[0]!)]);
  ctx.io.stdout.write(secret!.value + (ctx.io.stdout.isTTY ? "\n" : ""));
  return { exitCode: EXIT.ok };
}

async function cmdInject(ctx: Context): Promise<RunResult> {
  const { parsed, io } = ctx;
  if (parsed.positionals.length > 0) throw new CliError(EXIT.usage, "Usage: varn inject [-i <template>] [-o <file>]");
  const input = one(parsed, "--in");
  const output = one(parsed, "--out");
  let template: string;
  if (input === undefined || input === "-") {
    template = await readStream(io.stdin());
  } else {
    try {
      template = await readFile(ctx.path(input), "utf8");
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      throw new CliError(EXIT.io, `Could not read the template ${input}${code ? ` (${code})` : ""}.`);
    }
  }
  const raws = [...new Set([...template.matchAll(PLACEHOLDER)].map((m) => m[1]!))];
  const resolved = await ctx.resolve(raws.map(parseReference));
  const values = new Map(resolved.map((r) => [r.reference.raw, r.value]));
  const result = template.replace(PLACEHOLDER, (_, raw: string) => values.get(raw)!);
  if (raws.length === 0) ctx.warn("the template has no {{ varn://… }} placeholders.");
  if (output === undefined || output === "-") io.stdout.write(result);
  else await writePrivateFile(ctx.path(output), result);
  return { exitCode: EXIT.ok };
}

async function cmdRun(ctx: Context): Promise<RunResult> {
  const { parsed, io } = ctx;
  const [command, ...args] = parsed.rest;
  if (!command) throw new CliError(EXIT.usage, "Usage: varn run [--no-masking] [--env-file <file>] -- <command> [args…]");

  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(io.env)) if (value !== undefined) env[key] = value;
  for (const file of parsed.options.get("--env-file") ?? []) {
    for (const [key, value] of await readEnvFile(ctx.path(file))) env[key] = value;
  }
  // The command does not need the machine token; do not hand it on.
  delete env[TOKEN_ENV];

  const names = Object.keys(env).filter((key) => isReference(env[key]!));
  const refs = names.map((name) => {
    try {
      return parseReference(env[name]!);
    } catch (error) {
      if (error instanceof CliError) throw new CliError(error.exitCode, `${name}: ${error.message}`);
      throw error;
    }
  });
  if (refs.length === 0) ctx.warn("no environment variable holds a varn:// reference; running the command unchanged.");
  const resolved = await ctx.resolve(refs);
  resolved.forEach((secret, i) => {
    if (secret.value.includes("\0")) throw new CliError(EXIT.badReference, `${names[i]}: the value contains a NUL character and cannot be put in an environment variable.`);
    env[names[i]!] = secret.value;
  });

  return runCommand({
    command,
    args,
    env,
    secrets: resolved.map((r) => r.value),
    masking: !flag(parsed, "--no-masking"),
    stdout: io.stdout,
    stderr: io.stderr,
    cwd: io.cwd,
    signals: io.signals,
    platform: io.platform,
  });
}

const COMMANDS: Record<string, { spec: Spec; stopAtPositional: boolean; run: (ctx: Context) => Promise<RunResult> }> = {
  read: { spec: {}, stopAtPositional: false, run: cmdRead },
  inject: { spec: { "--in": { value: true, alias: "-i" }, "--out": { value: true, alias: "-o" } }, stopAtPositional: false, run: cmdInject },
  run: { spec: { "--no-masking": { value: false }, "--env-file": { value: true, repeat: true } }, stopAtPositional: true, run: cmdRun },
};

async function dispatch(io: CliIO): Promise<RunResult> {
  const argv = [...io.argv];
  // Global options may come before the command.
  const leading: string[] = [];
  while (argv.length > 0 && argv[0]!.startsWith("-")) {
    const arg = argv.shift()!;
    if (arg === "--version" || arg === "-V") {
      io.stdout.write(`${VERSION}\n`);
      return { exitCode: EXIT.ok };
    }
    if (arg === "--help" || arg === "-h") {
      io.stdout.write(HELP.main);
      return { exitCode: EXIT.ok };
    }
    leading.push(arg);
    if (arg === "--token-file" && argv.length > 0) leading.push(argv.shift()!);
  }
  const name = argv.shift();
  if (name === undefined) {
    io.stderr.write(HELP.main);
    return { exitCode: EXIT.usage };
  }
  if (name === "version") {
    io.stdout.write(`${VERSION}\n`);
    return { exitCode: EXIT.ok };
  }
  if (name === "help") {
    const topic = argv[0];
    io.stdout.write(topic && topic in HELP ? HELP[topic as keyof typeof HELP] : HELP.main);
    return { exitCode: EXIT.ok };
  }
  const command = COMMANDS[name];
  if (!command) throw new CliError(EXIT.usage, `Unknown command ${JSON.stringify(name)}. Commands: read, run, inject, help.`);
  const parsed = parseArgs([...leading, ...argv], command.spec, command.stopAtPositional);
  if (flag(parsed, "--help")) {
    io.stdout.write(HELP[name as keyof typeof HELP]);
    return { exitCode: EXIT.ok };
  }
  return command.run(new Context(io, parsed));
}

/** Runs the CLI; never throws. */
export async function main(io: CliIO): Promise<RunResult> {
  try {
    return await dispatch(io);
  } catch (error) {
    if (error instanceof CliError) {
      io.stderr.write(`varn: ${error.message}\n`);
      return { exitCode: error.exitCode };
    }
    // Unexpected: report the kind only, never a message that might carry data.
    const kind = error instanceof Error ? error.name : typeof error;
    io.stderr.write(`varn: internal error (${kind}). Please report this, with the varn version (${VERSION}).\n`);
    return { exitCode: EXIT.internal };
  }
}
