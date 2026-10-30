/**
 * Builds packages/cli/dist/varn.mjs: one ESM file with a shebang, the shared
 * vault modules (src/domain/vault/*) and Zod bundled in, so the published
 * package has no runtime dependencies. Not minified, so what runs can be
 * read; deterministic, so the same commit gives the same file.
 *
 *   npm run build:cli
 */
import { build, type Plugin } from "esbuild";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
export const CLI_ROOT = path.resolve(here, "..");
const REPO_ROOT = path.resolve(CLI_ROOT, "..", "..");

/**
 * Zod re-exports all ~60 of its message locales as `z.locales`, which a
 * bundler cannot drop. The CLI only ever shows Zod's English default (and
 * never Zod messages to users at all), so the locale index is replaced by one
 * that exports English only. That roughly halves the bundle and the code a
 * reviewer has to read. The build fails if the import is no longer found.
 */
function englishOnlyZodLocales(stubbed: { count: number }): Plugin {
  return {
    name: "zod-english-only-locales",
    setup(b) {
      b.onResolve({ filter: /^\.\.\/locales\/index\.js$/ }, (args) => {
        if (!/[\\/]zod[\\/]v4[\\/](classic|core)[\\/]/.test(args.importer)) return undefined;
        stubbed.count++;
        // A path relative to the repository, so no local path ends up in the bundle.
        const en = path.relative(REPO_ROOT, path.join(path.dirname(args.importer), "..", "locales", "en.js")).replace(/\\/g, "/");
        return { path: en, namespace: "zod-locales-en" };
      });
      b.onLoad({ filter: /.*/, namespace: "zod-locales-en" }, (args) => ({
        contents: `export { default as en } from ${JSON.stringify(`./${args.path}`)};`,
        loader: "js",
        resolveDir: REPO_ROOT,
      }));
    },
  };
}

export async function buildCli(outDir = path.join(CLI_ROOT, "dist")): Promise<string> {
  const stubbed = { count: 0 };
  await mkdir(outDir, { recursive: true });
  const outfile = path.join(outDir, "varn.mjs");
  await build({
    entryPoints: [path.join(CLI_ROOT, "src", "bin.ts")],
    outfile,
    bundle: true,
    platform: "node",
    format: "esm",
    target: "node20",
    banner: { js: "#!/usr/bin/env node" },
    legalComments: "eof",
    sourcemap: false,
    minify: false,
    logLevel: "warning",
    // Nothing may be left external except Node's own modules.
    packages: "bundle",
    absWorkingDir: REPO_ROOT,
    plugins: [englishOnlyZodLocales(stubbed)],
  });
  if (stubbed.count === 0) throw new Error("build:cli: zod's locale index was not found; check englishOnlyZodLocales against the installed zod.");
  const zodLicense = await readFile(path.join(REPO_ROOT, "node_modules", "zod", "LICENSE"), "utf8");
  await writeFile(
    path.join(outDir, "THIRD-PARTY-LICENSES.txt"),
    `dist/varn.mjs bundles the following third-party software.\n\n== zod (https://zod.dev) ==\n\n${zodLicense}`,
  );
  return outfile;
}

// Run directly (tsx packages/cli/scripts/build.ts), not when imported by a test.
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const outfile = await buildCli();
  // Executable bit, for running dist/varn.mjs directly (npm sets it on install anyway).
  await chmod(outfile, 0o755);
  process.stdout.write(`built ${path.relative(REPO_ROOT, outfile)}\n`);
}
