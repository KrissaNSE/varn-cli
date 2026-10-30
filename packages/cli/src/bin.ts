/**
 * Entry point of dist/varn.mjs: wires `main` to the real process. When the
 * command run by `varn run` was ended by a signal, varn ends itself with the
 * same signal so the caller (a shell, CI) sees what happened.
 */
import { main } from "./main";

const major = Number(process.versions.node.split(".")[0]);
if (!(major >= 20)) {
  process.stderr.write(`varn: Node.js 20 or newer is required (this is ${process.version}).\n`);
  process.exit(1);
}

// `varn read … | head -c 3` closes stdout early; that is not an error.
for (const stream of [process.stdout, process.stderr]) {
  stream.on("error", (error: NodeJS.ErrnoException) => {
    if (error.code === "EPIPE") process.exit(process.exitCode ?? 0);
    throw error;
  });
}

const result = await main({
  argv: process.argv.slice(2),
  env: process.env,
  stdout: process.stdout,
  stderr: process.stderr,
  stdin: () => process.stdin,
  cwd: process.cwd(),
});

// If the signal below does not end the process, it exits with 128 + the signal number (the shell convention).
process.exitCode = result.exitCode;
if (result.signal && process.platform !== "win32") {
  process.removeAllListeners(result.signal);
  process.kill(process.pid, result.signal);
}
