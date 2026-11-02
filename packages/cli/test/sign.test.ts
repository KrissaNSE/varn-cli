import { describe, expect, it } from "vitest";
import { createRequestSigner } from "../src/sign";
import { generateMachineSigningKey, parseSignatureHeader, verifyRequestSignature, type MachineToken } from "../../../src/domain/vault/crypto";
import { signedString } from "../../../src/domain/vault/machine-api";

describe("createRequestSigner", () => {
  it("signs with the given clock and the signature verifies over the shared signed string", async () => {
    const { signingSecret, signingPublicKey } = await generateMachineSigningKey();
    const token = { signingSecret } as unknown as MachineToken;
    const signer = createRequestSigner(token, "verifier-b64")!;
    const ids = ["b0000000-0000-4000-8000-000000000002", "a0000000-0000-4000-8000-000000000001"];
    const header = signer.header("GET", "/api/vault/v1/collections", ids, 1_800_000_000);
    const parsed = parseSignatureHeader(header)!;
    expect(parsed.t).toBe(1_800_000_000);
    const signed = signedString({ method: "GET", path: "/api/vault/v1/collections", ids, timestamp: parsed.t, verifier: "verifier-b64" });
    expect(await verifyRequestSignature({ signingPublicKey, signed, signature: parsed.sig })).toBe(true);
    expect(await verifyRequestSignature({ signingPublicKey, signed: signed + "x", signature: parsed.sig })).toBe(false);
  });

  it("returns null for a token without a signing scalar", () => {
    expect(createRequestSigner({} as MachineToken, "v")).toBeNull();
  });
});
