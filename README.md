# varn-cli

Source of [`@varnsecurity/cli`](https://www.npmjs.com/package/@varnsecurity/cli), the command-line tool for [Värn](https://www.varnsecurity.se)'s vault: it resolves `varn://` secret references on the machine that needs them, so secrets stay out of code, `.env` files and CI settings. Secrets are decrypted on that machine; Värn never sees them in plaintext.

**Usage, commands and the GitHub Action:** [packages/cli/README.md](packages/cli/README.md). Customer guide: [Hemligheter i kod och CI](https://www.varnsecurity.se/docs/hemligheter-i-kod-och-ci) · [Secrets in code and CI](https://www.varnsecurity.se/en/docs/secrets-in-code-and-ci).

This repository is a read-only mirror, published automatically from Värn's main repository so that every npm release can be traced to its source (npm provenance). It contains the CLI and the vault crypto it bundles (`src/domain/vault/`), the same code the Värn web app runs in the browser.

```bash
npm ci
npm test            # CLI tests, including end-to-end decryption against generated fixtures
npm run build:cli   # packages/cli/dist/varn.mjs, deterministic and unminified
```

Security issues: security@varnsecurity.se. Licence: MIT.
