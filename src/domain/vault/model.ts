/**
 * Vault item format, limits and the passphrase rule.
 *
 * The plaintext item only ever exists in the browser. The limits here are
 * mirrored by check constraints in supabase/migrations/20261029000100_vault_collections.sql
 * (on the ciphertext sizes) and by Zod in the Server Actions.
 * See docs/VAULT-THREAT-MODEL.md.
 */
import { z } from "zod";

export const VAULT_LIMITS = {
  nameMax: 200,
  usernameMax: 320,
  passwordMax: 1_000,
  urlMax: 2_048,
  notesMax: 10_000,
  fileNameMax: 255,
  fileTypeMax: 127,
  /** Largest file a user can attach. Keeps one request under Next.js' 1 MB Server Action limit. */
  fileMaxBytes: 512 * 1024,
  /** Largest padded item plaintext (UTF-8 JSON). */
  itemPlaintextMaxBytes: 64 * 1024,
  /** Base64 length limits, mirrored in the database. */
  itemCiphertextMaxChars: 90_000,
  fileCiphertextMaxChars: 700_000,
  itemsPerOrg: 1_000,
  /** Collection names (plaintext, characters). */
  collectionNameMax: 100,
  /** Base64 length limit of an encrypted collection name, mirrored in the database. */
  collectionNameCiphertextMaxChars: 1_000,
  /** Collections per organisation (abuse limit, not a plan limit). */
  collectionsPerOrg: 100,
} as const;

/** Item plaintext is padded to this many bytes so ciphertext sizes reveal little. */
export const ITEM_PADDING_BYTES = 256;
/** File plaintext is zero-padded to this many bytes. */
export const FILE_PADDING_BYTES = 4_096;
/** Collection-name plaintext is padded to this many bytes. */
export const COLLECTION_NAME_PADDING_BYTES = 128;

export const PASSPHRASE_MIN_LENGTH = 14;

const SHA256_HEX = /^[0-9a-f]{64}$/;

export const vaultFileMetaSchema = z.object({
  name: z.string().min(1).max(VAULT_LIMITS.fileNameMax),
  type: z.string().max(VAULT_LIMITS.fileTypeMax),
  size: z.number().int().min(0).max(VAULT_LIMITS.fileMaxBytes),
  sha256: z.string().regex(SHA256_HEX),
});

export const vaultItemPayloadSchema = z.object({
  v: z.literal(1),
  name: z.string().trim().min(1).max(VAULT_LIMITS.nameMax),
  username: z.string().max(VAULT_LIMITS.usernameMax),
  password: z.string().max(VAULT_LIMITS.passwordMax),
  url: z.string().max(VAULT_LIMITS.urlMax),
  notes: z.string().max(VAULT_LIMITS.notesMax),
  file: vaultFileMetaSchema.nullable(),
});

/** Plaintext of a collection's encrypted name. An object so later versions can add fields. */
export const collectionNamePayloadSchema = z.object({
  v: z.literal(1),
  name: z.string().trim().min(1).max(VAULT_LIMITS.collectionNameMax),
});

export type VaultFileMeta = z.infer<typeof vaultFileMetaSchema>;
export type VaultItemPayload = z.infer<typeof vaultItemPayloadSchema>;

export function emptyItem(): VaultItemPayload {
  return { v: 1, name: "", username: "", password: "", url: "", notes: "", file: null };
}

/**
 * One CSV cell: quoted, with quotes doubled. A leading = + - @ (or tab/CR) is
 * prefixed with ' so a spreadsheet never runs a stored value as a formula.
 */
function csvCell(value: string): string {
  const safe = /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
  return `"${safe.replace(/"/g, '""')}"`;
}

/**
 * Plain-text export of decrypted items, built in the browser only (the server
 * never sees it). Columns follow the generic CSV import of common password
 * managers, with the collection's name first (importers that know "folder" or
 * "collection" can map it; others ignore it). Attached files are named in the
 * notes and downloaded separately.
 */
export function vaultItemsToCsv(items: { collection: string; item: VaultItemPayload }[], attachedFileLabel: string): string {
  const header = ["collection", "name", "url", "username", "password", "notes"];
  const rows = items.map(({ collection, item }) => {
    const notes = item.file ? [item.notes, `${attachedFileLabel}: ${item.file.name}`].filter(Boolean).join("\n") : item.notes;
    return [collection, item.name, item.url, item.username, item.password, notes].map(csvCell).join(",");
  });
  return `\uFEFF${[header.join(","), ...rows].join("\r\n")}\r\n`;
}

export type PassphraseProblem = "too_short" | "too_repetitive" | "mismatch";

/**
 * Minimum rule for a vault passphrase. It protects the wrapped private key
 * against offline guessing (threat V5), so it is stricter than the account
 * password: at least 14 characters and not one or two repeated characters.
 * The UI recommends four or more random words.
 */
export function passphraseProblem(passphrase: string, confirmation?: string): PassphraseProblem | null {
  const normalized = passphrase.normalize("NFKC");
  if ([...normalized].length < PASSPHRASE_MIN_LENGTH) return "too_short";
  if (new Set(normalized.toLowerCase()).size < 5) return "too_repetitive";
  if (confirmation !== undefined && confirmation.normalize("NFKC") !== normalized) return "mismatch";
  return null;
}

/** Only http(s) links are rendered as links; anything else is shown as text. */
export function safeItemUrl(url: string): string | null {
  try {
    const parsed = new URL(url.trim());
    return parsed.protocol === "https:" || parsed.protocol === "http:" ? parsed.toString() : null;
  } catch {
    return null;
  }
}
