# @varnsecurity/cli

`varn` resolves **secret references** such as

```
varn://exempel/Produktion/Produktionsdatabas/password
```

from your organisation's Värn secure vault, on the machine that needs them. It fetches only ciphertext from Värn, decrypts it locally with the private key in a machine account's token, and gives the value to your program. Värn never sees the plaintext or any key that can decrypt it.

> **Status:** built, not launched. The secure vault, machine accounts and this tool launch after an independent security review. Until then the API answers `503 vault_disabled`.

* Node.js 20 or newer, no runtime dependencies (one bundled file).
* Commands: `varn run`, `varn read`, `varn inject`.
* Customer docs: <https://www.varnsecurity.se/docs/hemligheter-i-kod-och-ci> (Swedish), <https://www.varnsecurity.se/en/docs/secrets-in-code-and-ci> (English).

## Install

Always pin an exact version.

```bash
npx --yes @varnsecurity/cli@0.1.0 --version        # run without installing
npm install --global @varnsecurity/cli@0.1.0       # or install
npm install --save-dev --save-exact @varnsecurity/cli@0.1.0
```

### Verify the package (provenance)

Every release is built and published by GitHub Actions with [npm provenance](https://docs.npmjs.com/generating-provenance-statements): the registry holds a signed statement of which repository, commit and workflow produced the tarball.

```bash
# In a project that has @varnsecurity/cli installed: checks registry signatures and provenance attestations.
npm audit signatures

# The provenance statement of one version (source commit and workflow):
npm view @varnsecurity/cli@0.1.0 dist.attestations --json
```

On npmjs.com the version page shows "Built and signed on GitHub Actions" with a link to the commit. The build is deterministic: checking out that commit and running `npm ci && npm run build:cli` gives a `packages/cli/dist/varn.mjs` with the same SHA-256 as the one in the tarball (`npm pack @varnsecurity/cli@0.1.0` and unpack it to compare).

## Token

A machine account is created by an administrator in Värn under **Secure vault → Machine accounts** (Business and Enterprise). It is read-only, limited to chosen collections, expires (at most one year), can be limited to IP ranges and can be revoked at once. Its token is shown once.

`varn` reads the token from:

1. `--token-file <path>` – a file holding just the token, or the text file Värn offers for download when the account is created; or
2. the environment variable `VARN_TOKEN`.

The token contains the machine's private key. `varn` sends only a value derived from it (`Authorization: Bearer …`, which cannot decrypt anything), never prints the token, and removes `VARN_TOKEN` from the environment of the command it runs.

## References

```
varn://<organisation>/<collection>/<item>/<field>
```

| Part | |
|---|---|
| `organisation` | The organisation's slug in Värn (as in `/o/<slug>/…`). Must be the token's organisation. |
| `collection` | The collection's name, or `id:<uuid>`. |
| `item` | The item's name, or `id:<uuid>`. |
| `field` | `password`, `username`, `url` or `notes`. |

* Names are case-insensitive and URL-encoded (`%20` for a space, `%2F` for `/`, `%3F` for `?`, `%23` for `#`). Whether a part is an id is decided before decoding, so an item really named `id:x` is written `id%3Ax`.
* Names are resolved on the machine: Värn's API never receives a name, and cannot resolve one (names are encrypted).
* A name that matches more than one collection or item is an error (exit code 10); the message lists the ids so you can use `id:` or rename one.
* An empty field is an error (exit code 9), so a typo never turns into an empty password.

## Commands

### `varn run [--no-masking] [--env-file <file>]… -- <command> [args…]`

Starts `<command>` with every environment variable whose value is a `varn://` reference replaced by the secret.

* References come from the current environment and from `--env-file` files (`KEY=value` lines, `#` comments, `export` prefixes, single or double quotes; one variable per line). File values take precedence over the environment; several files are read in order.
* **Masking (default):** any secret value the command prints on stdout or stderr is replaced with `<varn:concealed>`, also when it is printed in several pieces. Only exact values are masked, not encodings of them (base64, URL encoding, …). With masking, stdout and stderr are pipes, so the command does not see a terminal on them (colours may turn off). `--no-masking` passes the terminal through unchanged.
* stdin is inherited. SIGINT, SIGTERM, SIGHUP, SIGQUIT and SIGUSR2 (SIGINT, SIGBREAK and SIGHUP on Windows) are forwarded. `varn` exits with the command's exit code, or ends itself with the signal that ended the command.
* With no references at all the command runs unchanged (with a warning) and no token is needed.
* On Windows, commands other than `.exe`/`.com` (such as `npm`, which is `npm.cmd`) are run through `cmd.exe`.

```bash
export VARN_TOKEN=varn_mt_…
DATABASE_PASSWORD=varn://exempel/Produktion/Produktionsdatabas/password varn run -- npm start
varn run --env-file .env.production -- node server.js
```

### `varn read <reference>`

Prints one value on stdout, with a trailing newline only when stdout is a terminal (so `$(varn read …)` is exact).

```bash
PGPASSWORD="$(varn read varn://exempel/Produktion/Produktionsdatabas/password)" psql …
```

### `varn inject [-i <template>] [-o <file>]`

Replaces every `{{ varn://… }}` placeholder in a template (from `-i`, or stdin) and writes the result to `-o` or stdout. With `-o` the file is created with mode `0600` and replaced atomically (a temporary file in the same directory, then a rename). Nothing is written if any reference fails. This is the only command that writes secrets to disk.

```bash
varn inject -i config.yml.tpl -o config.yml
```

### Other

* `varn --version` (or `varn version`), `varn help [command]`, `varn <command> --help`.
* `--verbose` prints, on stderr, which item version each reference resolved to and when it was last updated (threat M7 in the design: notice a stale value).
* `varn` warns on stderr when the machine account expires within 14 days.

## Environment

| Variable | Default | |
|---|---|---|
| `VARN_TOKEN` | – | The machine token (or use `--token-file`). |
| `VARN_API_URL` | `https://www.varnsecurity.se` | Only the origin is used. Must be `https://`; plain `http://` is accepted only for `localhost`, `*.localhost`, `127.0.0.1` and `[::1]`. |

## GitHub Actions

Store the token as a repository or environment secret (`VARN_TOKEN`), and use a GitHub environment with protection rules for production tokens.

### Directly with npx (simplest)

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - name: Deploy
        run: npx --yes @varnsecurity/cli@0.1.0 run -- ./deploy.sh
        env:
          VARN_TOKEN: ${{ secrets.VARN_TOKEN }}
          DATABASE_PASSWORD: varn://exempel/Produktion/Produktionsdatabas/password
          STRIPE_KEY: varn://exempel/Produktion/Stripe/password
```

The values exist only in that step, and everything `deploy.sh` prints is masked.

### The action

`packages/cli/action` is a composite action around the CLI (inputs are passed to the shell only through environment variables):

| Input | Default | |
|---|---|---|
| `token` | (required) | The machine token, e.g. `${{ secrets.VARN_TOKEN }}`. |
| `version` | `0.1.0` | Exact `@varnsecurity/cli` version; ranges and `latest` are refused. |
| `run` | | A bash command run with `varn run` (masked); references in the step's or job's `env` are resolved. |
| `env-file` | | An env file for `run`. |
| `masking` | `true` | `false` turns masking off for `run`. |
| `export` | | `NAME=varn://…` lines: resolved once and exported to the **later steps of the job** as environment variables, each registered with `::add-mask::`. |
| `api-url` | | Värn's address if not the default. |

```yaml
      - uses: KrissaNSE/varn-cli/packages/cli/action@cli-v0.1.0   # pin a tag or, better, a commit SHA
        with:
          token: ${{ secrets.VARN_TOKEN }}
          run: ./deploy.sh
        env:
          DATABASE_PASSWORD: varn://exempel/Produktion/Produktionsdatabas/password

      - uses: KrissaNSE/varn-cli/packages/cli/action@cli-v0.1.0
        with:
          token: ${{ secrets.VARN_TOKEN }}
          export: |
            DATABASE_PASSWORD=varn://exempel/Produktion/Produktionsdatabas/password
            STRIPE_KEY=varn://exempel/Produktion/Stripe/password
      - run: ./migrate.sh     # sees DATABASE_PASSWORD and STRIPE_KEY; GitHub masks them in the log
```

Prefer `run`: with `export`, every later step of the job (including third-party actions) can read the values. A composite action cannot declare outputs with names chosen by the caller, so `export` uses environment variables rather than step outputs. The action needs Node.js 20+ on the runner (GitHub-hosted runners have it; otherwise add `actions/setup-node`).

## Security notes

* **What leaves the machine:** one HTTPS `GET /api/vault/v1/collections` (with `?ids=` when every reference names its collection by id), with the bearer value derived from the token. No names, references or values are sent. Redirects are never followed (the bearer value is not handed to another host).
* **What is checked:** the response must match the v1 schema, be for the token's organisation and machine, and the machine's public key must belong to the token. Collection keys are unwrapped only from grants that authenticate the sending administrator's key (sender-authenticated, as for people). Collections or items that do not decrypt are skipped with a warning and never used.
* **Nothing is cached or written** except by `varn inject -o`. Values live in memory only.
* **Errors** name references, ids and API error codes; never the token, the bearer value or a secret.
* **Masking is a safety net, not a guarantee:** a program that transforms a value before printing it (base64, hex, partial output) is not caught.
* **If a token leaks:** revoke the machine account in Värn, rotate the collections it could read, and change the real secrets.

## Exit codes

| Code | |
|---|---|
| 0 | Success |
| 1 | Internal error (a bug) |
| 2 | Usage: unknown command/option, missing argument |
| 3 | Invalid reference (syntax, unknown field) |
| 4 | Token missing, malformed or unreadable |
| 5 | `VARN_API_URL` invalid or not HTTPS |
| 6 | Network error, timeout, redirect, or a response that is not API v1 |
| 7 | 401 `unauthorized`: unknown, revoked or expired token, or a call from outside the allowed networks |
| 8 | 403 `not_entitled` |
| 9 | Not found: 404 `collection_not_found`, no such collection/item, or an empty field |
| 10 | Ambiguous name |
| 11 | 429 `rate_limited` (60 requests a minute per machine and per IP) |
| 12 | 503 `vault_disabled` |
| 13 | 500 `server_error`, 400 `invalid_request` or another unexpected status |
| 14 | Decryption failed, or the response is for another organisation/machine |
| 15 | The reference names another organisation than the token's |
| 16 | A template or env file could not be read, or the output not written |
| 126 / 127 | `varn run`: the command could not be executed / was not found |

Once `varn run` has started the command, the exit code is the command's.

## Development

The source is in `packages/cli/src` and imports the vault's crypto, item model and API schema straight from the web app (`src/domain/vault/*`), so the CLI and the app cannot drift apart. From the repository root:

```bash
npm run build:cli                     # → packages/cli/dist/varn.mjs (esbuild, one ESM file, Zod bundled)
node packages/cli/dist/varn.mjs --version
npx vitest run packages/cli           # also part of npm test
```

The tests build real vault fixtures with the shared crypto (organisation, member, collections, items, machine account and grants), serve the read API from a local HTTP server, and run `read`, `inject` and `run` against it, including the built bundle.

## Publishing (maintainers)

The source lives in Värn's private repository. `.github/workflows/sync-cli-mirror.yml` there copies `packages/cli` and the vault modules it bundles to the public repository [KrissaNSE/varn-cli](https://github.com/KrissaNSE/varn-cli) on every push to `main` (`packages/cli/mirror/assemble.mjs` decides what goes public). Releases are published from the public repository, because npm provenance and a GitHub Action customers can use both need one.

1. Bump `version` in `packages/cli/package.json` and the action's default `version`, merge to `main` in the private repository and wait for the mirror sync.
2. In KrissaNSE/varn-cli: `git tag cli-v<version> && git push origin cli-v<version>`. Its `publish.yml` runs only for that tag, checks that it matches `packages/cli/package.json`, runs the tests, builds and runs `npm publish --provenance --access public` with the `NPM_TOKEN` secret of its environment `npm` (a granular token for the `@varnsecurity` organisation, which requires 2FA).

Licence: MIT.
