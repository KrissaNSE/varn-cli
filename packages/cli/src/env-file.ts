/**
 * A small .env parser for `varn run --env-file`:
 *
 *   # comment
 *   KEY=value                 unquoted: trimmed, a " #" starts a comment
 *   export KEY=value          "export " is ignored
 *   KEY='literal value'       single quotes: taken as is
 *   KEY="a\nb"                double quotes: \n \r \t \" \\ are unescaped
 *
 * One variable per line; values do not span lines. Errors name the file and
 * line number, never the line's content (it may hold a secret).
 */
import { readFile } from "node:fs/promises";
import { CliError, EXIT } from "./errors";

const KEY = /^[A-Za-z_][A-Za-z0-9_]*$/;

export function parseEnvFile(content: string, name: string): Map<string, string> {
  const vars = new Map<string, string>();
  const lines = content.replace(/^\uFEFF/, "").split(/\r?\n/);
  lines.forEach((line, index) => {
    const trimmed = line.trim();
    if (trimmed === "" || trimmed.startsWith("#")) return;
    const fail = (why: string) => new CliError(EXIT.io, `${name}, line ${index + 1}: ${why}.`);
    const body = trimmed.startsWith("export ") ? trimmed.slice(7).trimStart() : trimmed;
    const eq = body.indexOf("=");
    if (eq <= 0) throw fail("expected KEY=value");
    const key = body.slice(0, eq).trim();
    if (!KEY.test(key)) throw fail("the variable name may only contain letters, digits and _, and not start with a digit");
    let value = body.slice(eq + 1).trim();
    const quote = value[0];
    if (quote === '"' || quote === "'") {
      // Single quotes end at the next ', double quotes at the next unescaped ".
      let close = quote === "'" ? value.indexOf("'", 1) : -1;
      if (quote === '"') {
        for (let i = 1; i < value.length; i++) {
          if (value[i] === "\\") i++;
          else if (value[i] === '"') {
            close = i;
            break;
          }
        }
      }
      if (close === -1) throw fail("the quoted value is not closed on the same line");
      const after = value.slice(close + 1).trim();
      if (after !== "" && !after.startsWith("#")) throw fail("unexpected text after the closing quote");
      const inner = value.slice(1, close);
      value =
        quote === "'"
          ? inner
          : inner.replace(/\\([nrt"\\])/g, (_, c: string) => ({ n: "\n", r: "\r", t: "\t", '"': '"', "\\": "\\" })[c] ?? c);
    } else {
      const comment = value.search(/\s#/);
      if (comment !== -1) value = value.slice(0, comment).trimEnd();
    }
    vars.set(key, value);
  });
  return vars;
}

export async function readEnvFile(path: string): Promise<Map<string, string>> {
  let content: string;
  try {
    content = await readFile(path, "utf8");
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    throw new CliError(EXIT.io, `Could not read the env file ${path}${code ? ` (${code})` : ""}.`);
  }
  return parseEnvFile(content, path);
}
