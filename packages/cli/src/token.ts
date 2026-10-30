/**
 * Finding and parsing the machine token. The token is read from `--token-file`
 * if given, otherwise from `VARN_TOKEN`. It is never printed, logged or passed
 * on: `varn run` removes VARN_TOKEN from the command's environment.
 */
import { readFile, stat } from "node:fs/promises";
import { MACHINE_TOKEN_PREFIX, parseMachineToken, type MachineToken } from "../../../src/domain/vault/crypto";
import { CliError, EXIT } from "./errors";

export const TOKEN_ENV = "VARN_TOKEN";

export interface TokenSource {
  env: Record<string, string | undefined>;
  tokenFile?: string;
  warn: (message: string) => void;
  platform?: NodeJS.Platform;
}

async function readTokenFile(path: string, opts: TokenSource): Promise<string> {
  try {
    if ((opts.platform ?? process.platform) !== "win32") {
      const info = await stat(path);
      if ((info.mode & 0o077) !== 0) {
        opts.warn(`The token file ${path} can be read by other users; restrict it with: chmod 600 ${path}`);
      }
    }
    return await readFile(path, "utf8");
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    throw new CliError(EXIT.token, `Could not read the token file ${path}${code ? ` (${code})` : ""}.`);
  }
}

/**
 * A token file holds either just the token, or the text file Värn offers for
 * download when a machine account is created (a title, the token on its own
 * line, the organisation, expiry and instructions). Exactly one line may start
 * with varn_mt_.
 */
export function tokenInFile(content: string): string {
  const lines = content.split(/\r?\n/).map((line) => line.trim());
  const tokens = lines.filter((line) => line.toLowerCase().startsWith(MACHINE_TOKEN_PREFIX));
  return tokens.length === 1 ? tokens[0]! : content;
}

export async function loadToken(opts: TokenSource): Promise<MachineToken> {
  let text: string | undefined;
  let where: string;
  if (opts.tokenFile !== undefined) {
    text = tokenInFile(await readTokenFile(opts.tokenFile, opts));
    where = `the token file ${opts.tokenFile}`;
  } else {
    text = opts.env[TOKEN_ENV];
    where = TOKEN_ENV;
    if (!text || !text.trim()) {
      throw new CliError(
        EXIT.token,
        `No machine token. Set ${TOKEN_ENV} to the token of a Värn machine account (Secure vault → Machine accounts), or pass --token-file <path>.`,
      );
    }
  }
  try {
    return await parseMachineToken(text);
  } catch {
    // Deliberately no detail: the error must not echo any part of the token.
    throw new CliError(
      EXIT.token,
      `The machine token in ${where} is not valid. It should start with varn_mt_ and be 117 characters long; copy it again from the file you downloaded when the machine account was created.`,
    );
  }
}
