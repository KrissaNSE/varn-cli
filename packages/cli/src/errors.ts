/**
 * Errors and exit codes of the `varn` CLI.
 *
 * Every failure the tool itself reports has its own exit code, so scripts can
 * tell "the token is wrong" from "the network is down". Messages never contain
 * the token, the bearer value or a secret value: they name references, ids and
 * error codes only.
 *
 * `varn run` exits with the command's own exit code once the command has
 * started; the codes below only apply before that.
 */

export const EXIT = {
  ok: 0,
  /** A bug in the tool. */
  internal: 1,
  /** Unknown command or option, missing argument. */
  usage: 2,
  /** A reference that is not `varn://<org>/<collection>/<item>/<field>`, or an unknown field. */
  badReference: 3,
  /** No token, or a token that is malformed or cannot be read. */
  token: 4,
  /** `VARN_API_URL` is invalid or not HTTPS. */
  config: 5,
  /** Connection, timeout, redirect or a response that is not the v1 contract. */
  network: 6,
  /** 401: unknown, revoked or expired token, or a call from outside the allowed networks. */
  unauthorized: 7,
  /** 403: the organisation's plan does not include the vault. */
  notEntitled: 8,
  /** A collection, item or field that the machine cannot see, or an empty field. */
  notFound: 9,
  /** A name that matches more than one collection or item. */
  ambiguous: 10,
  /** 429. */
  rateLimited: 11,
  /** 503: the vault is switched off. */
  vaultDisabled: 12,
  /** 500, 400 or any other unexpected status. */
  server: 13,
  /** A grant, collection name or item that does not decrypt, or a response for another machine. */
  decrypt: 14,
  /** A reference to another organisation than the token's. */
  wrongOrganization: 15,
  /** Reading a template or env file, or writing the output. */
  io: 16,
  /** `varn run`: the command could not be executed (shell convention). */
  commandNotExecutable: 126,
  /** `varn run`: the command was not found (shell convention). */
  commandNotFound: 127,
} as const;

export type ExitCode = (typeof EXIT)[keyof typeof EXIT];

export class CliError extends Error {
  constructor(
    public readonly exitCode: ExitCode,
    message: string,
  ) {
    super(message);
    this.name = "CliError";
  }
}
