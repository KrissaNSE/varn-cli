import { describe, expect, it } from "vitest";
import { CliError, EXIT } from "../src/errors";
import { PLACEHOLDER, isReference, nameKey, parseReference } from "../src/reference";

const UUID = "7f3c9a2e-1b4d-4c8e-9f00-0123456789ab";

describe("parseReference", () => {
  it("parses names, lower-casing the organisation and field", () => {
    expect(parseReference("varn://Exempel/Produktion/Databas/PASSWORD")).toEqual({
      raw: "varn://Exempel/Produktion/Databas/PASSWORD",
      org: "exempel",
      collection: { kind: "name", name: "Produktion" },
      item: { kind: "name", name: "Databas" },
      field: "password",
    });
  });

  it.each(["password", "username", "url", "notes"])("accepts the field %s", (field) => {
    expect(parseReference(`varn://o/c/i/${field}`).field).toBe(field);
  });

  it("URL-decodes names, so a name may contain spaces, slashes and non-ASCII letters", () => {
    const ref = parseReference("varn://exempel/Ekonomi%20%26%20l%C3%B6n/Bank%2FSEB/username");
    expect(ref.collection).toEqual({ kind: "name", name: "Ekonomi & lön" });
    expect(ref.item).toEqual({ kind: "name", name: "Bank/SEB" });
    expect(parseReference("varn://exempel/Ekonomi/Lön/url").item).toEqual({ kind: "name", name: "Lön" });
  });

  it("parses id: selectors and normalises the UUID to lower case", () => {
    const ref = parseReference(`varn://exempel/id:${UUID.toUpperCase()}/ID:${UUID}/notes`);
    expect(ref.collection).toEqual({ kind: "id", id: UUID });
    expect(ref.item).toEqual({ kind: "id", id: UUID });
  });

  it("treats an encoded id%3A… as a name", () => {
    expect(parseReference("varn://exempel/c/id%3Asomething/password").item).toEqual({ kind: "name", name: "id:something" });
  });

  it("compares names case-insensitively and in Unicode NFC", () => {
    expect(nameKey("PRODUKTION")).toBe(nameKey("produktion"));
    expect(nameKey("Lön")).toBe(nameKey("LÖN"));
  });

  it.each([
    ["no scheme", "exempel/c/i/password"],
    ["another scheme", "op://exempel/c/i/password"],
    ["too few segments", "varn://exempel/c/password"],
    ["too many segments", "varn://exempel/c/i/password/extra"],
    ["a trailing slash", "varn://exempel/c/i/password/"],
    ["an empty organisation", "varn:///c/i/password"],
    ["an empty collection", "varn://exempel//i/password"],
    ["an empty item", "varn://exempel/c//password"],
    ["an unknown field", "varn://exempel/c/i/secret"],
    ["a custom field", "varn://exempel/c/i/api_key"],
    ["a raw space", "varn://exempel/c/my item/password"],
    ["a query", "varn://exempel/c/i/password?x=1"],
    ["a fragment", "varn://exempel/c/i#x/password"],
    ["broken URL encoding", "varn://exempel/c/%E0%A4%A/password"],
    ["an id that is not a UUID", "varn://exempel/id:123/i/password"],
    ["an empty id", "varn://exempel/c/id:/password"],
  ])("refuses %s", (_, raw) => {
    let error: unknown;
    try {
      parseReference(raw);
    } catch (e) {
      error = e;
    }
    expect(error).toBeInstanceOf(CliError);
    expect((error as CliError).exitCode).toBe(EXIT.badReference);
    expect((error as CliError).message).toContain("Invalid reference");
  });

  it("recognises references by their prefix only", () => {
    expect(isReference("varn://a/b/c/password")).toBe(true);
    expect(isReference(" varn://a/b/c/password")).toBe(false);
    expect(isReference("https://varn.example")).toBe(false);
  });
});

describe("template placeholders", () => {
  it("finds {{ varn://… }} with or without spaces", () => {
    const text = "a={{ varn://o/c/i/password }}\nb={{varn://o/c/i%20j/username}}\nc={{ not-a-ref }}\nd={ varn://o/c/i/url }";
    expect([...text.matchAll(PLACEHOLDER)].map((m) => m[1])).toEqual(["varn://o/c/i/password", "varn://o/c/i%20j/username"]);
  });
});
