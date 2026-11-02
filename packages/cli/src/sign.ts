/**
 * Request signing for the read API (token v2). The token carries the P-256
 * signing scalar; each request is signed over the string both sides build with
 * the shared `signedString`, so Värn can tell the bearer value alone is not
 * enough to read the vault.
 */
import { createPrivateKey, sign } from "node:crypto";
import type { MachineToken } from "../../../src/domain/vault/crypto";
import { signedString } from "../../../src/domain/vault/machine-api";

export interface RequestSigner {
  /** The `x-varn-signature` value: `v1,t=<unix seconds>,sig=<base64url r‖s>`. */
  header(method: string, path: string, ids: string[] | null, now?: number): string;
}

// ECPrivateKey (RFC 5915) for P-256 without the optional public key:
// SEQUENCE { INTEGER 1, OCTET STRING d, [0] OID prime256v1 }.
const SEC1_PREFIX = Buffer.from("30310201010420", "hex");
const SEC1_SUFFIX = Buffer.from("a00a06082a8648ce3d030107", "hex");

/** A signer for a v2 token; null for a v1 token, which has no signing scalar. */
export function createRequestSigner(token: MachineToken, verifier: string): RequestSigner | null {
  if (!token.signingSecret) return null;
  // Keep the DER copy of the scalar only as long as createPrivateKey needs it.
  const der = Buffer.concat([SEC1_PREFIX, token.signingSecret, SEC1_SUFFIX]);
  const key = createPrivateKey({ key: der, format: "der", type: "sec1" });
  der.fill(0);
  return {
    header(method, path, ids, now = Math.floor(Date.now() / 1000)) {
      const signed = signedString({ method, path, ids, timestamp: now, verifier });
      const signature = sign("sha256", Buffer.from(signed, "utf8"), { key, dsaEncoding: "ieee-p1363" });
      return `v1,t=${now},sig=${signature.toString("base64url")}`;
    },
  };
}
