// Part of the Värn secrets GitHub Action (action.yml, "export" mode). Runs
// under `varn run --env-file <file>`, so the variables named in <file> already
// hold the resolved values. For each one it registers the value with
// ::add-mask:: (so GitHub hides it in every later log line) and appends it to
// $GITHUB_ENV for the later steps of the job. It prints nothing else.
import { appendFileSync, readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";

const [file] = process.argv.slice(2);
const githubEnv = process.env.GITHUB_ENV;
if (!file || !githubEnv) {
  console.error("export.mjs: run by the Värn secrets action only (needs an env file and GITHUB_ENV).");
  process.exit(2);
}

// Workflow command data escaping (as in @actions/core).
const escape = (s) => s.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");

const names = readFileSync(file, "utf8")
  .split(/\r?\n/)
  .map((line) => line.trim())
  .filter((line) => line !== "" && !line.startsWith("#"))
  .map((line) => (line.startsWith("export ") ? line.slice(7).trimStart() : line))
  .map((line) => line.slice(0, line.indexOf("=")).trim());

for (const name of names) {
  const value = process.env[name] ?? "";
  if (value === "") continue;
  // GitHub masks per line, so a multi-line value is registered whole and line by line.
  for (const part of new Set([value, ...value.split(/\r?\n/)])) {
    if (part.trim() !== "") process.stdout.write(`::add-mask::${escape(part)}\n`);
  }
  let delimiter;
  do delimiter = `VARN_${randomBytes(16).toString("hex")}`;
  while (value.includes(delimiter));
  appendFileSync(githubEnv, `${name}<<${delimiter}\n${value}\n${delimiter}\n`);
}
