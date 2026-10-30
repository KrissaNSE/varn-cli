/**
 * `varn run`: starts a command with resolved secrets in its environment.
 *
 * With masking (the default) the command's stdout and stderr are piped through
 * ./mask.ts, so a value the command prints shows up as `<varn:concealed>`
 * (this protects CI logs; the command no longer sees a terminal on those two
 * streams). stdin is inherited. Signals that varn receives are forwarded to
 * the command, and varn exits with the command's exit code, or is ended by the
 * same signal that ended the command.
 */
import { spawn, type ChildProcess, type SpawnOptions } from "node:child_process";
import { constants } from "node:os";
import type { Readable, Writable } from "node:stream";
import { EXIT } from "./errors";
import { maskingStream } from "./mask";

export interface RunResult {
  exitCode: number;
  /** Set when the command was ended by a signal; the caller should end itself the same way. */
  signal?: NodeJS.Signals;
}

export interface SignalSource {
  on(signal: NodeJS.Signals, listener: () => void): unknown;
  off(signal: NodeJS.Signals, listener: () => void): unknown;
}

export interface RunOptions {
  command: string;
  args: string[];
  env: Record<string, string>;
  /** Values to mask; empty or `masking: false` turns masking off. */
  secrets: string[];
  masking: boolean;
  stdout: Writable;
  stderr: Writable;
  cwd?: string;
  signals?: SignalSource;
  platform?: NodeJS.Platform;
}

const FORWARDED: Record<"posix" | "win32", NodeJS.Signals[]> = {
  posix: ["SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT", "SIGUSR2"],
  win32: ["SIGINT", "SIGBREAK", "SIGHUP"],
};

/** Quotes one argument for cmd.exe. */
function cmdQuote(arg: string): string {
  return arg === "" || /[\s"&|<>^()%!,;=]/.test(arg) ? `"${arg.replace(/"/g, '""')}"` : arg;
}

/**
 * On Windows, programs such as npm and npx are .cmd scripts that Node can only
 * start through cmd.exe. Anything that is not an .exe/.com is therefore run as
 * one cmd.exe command line; elsewhere the command is executed directly.
 */
function spawnCommand(opts: RunOptions, stdio: SpawnOptions["stdio"]): ChildProcess {
  const platform = opts.platform ?? process.platform;
  const base: SpawnOptions = { env: opts.env as NodeJS.ProcessEnv, stdio, cwd: opts.cwd };
  if (platform === "win32" && !/\.(exe|com)$/i.test(opts.command)) {
    const line = [opts.command, ...opts.args].map(cmdQuote).join(" ");
    return spawn(line, { ...base, shell: true, windowsHide: false });
  }
  return spawn(opts.command, opts.args, base);
}

function pipeTo(source: Readable | null, target: Writable, mask: string[] | null): Promise<void> {
  if (!source) return Promise.resolve();
  return new Promise((resolve) => {
    const stream = mask ? source.pipe(maskingStream(mask)) : source;
    stream.pipe(target, { end: false });
    stream.on("end", () => resolve());
    stream.on("error", () => resolve());
  });
}

export function runCommand(opts: RunOptions): Promise<RunResult> {
  const masking = opts.masking && opts.secrets.length > 0;
  const inherit = !masking && opts.stdout === process.stdout && opts.stderr === process.stderr;
  const child = spawnCommand(opts, inherit ? "inherit" : ["inherit", "pipe", "pipe"]);
  const mask = masking ? opts.secrets : null;
  const output = Promise.all([pipeTo(child.stdout, opts.stdout, mask), pipeTo(child.stderr, opts.stderr, mask)]);

  const signals = opts.signals ?? process;
  const platform = opts.platform ?? process.platform;
  const forwarded = FORWARDED[platform === "win32" ? "win32" : "posix"];
  const listeners = forwarded.map((signal) => {
    const listener = () => {
      if (child.exitCode === null && child.signalCode === null) child.kill(signal);
    };
    signals.on(signal, listener);
    return [signal, listener] as const;
  });
  const cleanup = () => listeners.forEach(([signal, listener]) => signals.off(signal, listener));

  return new Promise<RunResult>((resolve) => {
    let settled = false;
    child.on("error", (error: NodeJS.ErrnoException) => {
      if (settled) return;
      settled = true;
      cleanup();
      const notFound = error.code === "ENOENT";
      opts.stderr.write(`varn: ${notFound ? "command not found" : `cannot run the command (${error.code ?? "error"})`}: ${opts.command}\n`);
      resolve({ exitCode: notFound ? EXIT.commandNotFound : EXIT.commandNotExecutable });
    });
    child.on("close", (code, signal) => {
      if (settled) return;
      settled = true;
      cleanup();
      void output.then(() => {
        if (signal) resolve({ exitCode: 128 + (constants.signals[signal] ?? 0), signal });
        else resolve({ exitCode: code ?? 1 });
      });
    });
  });
}
