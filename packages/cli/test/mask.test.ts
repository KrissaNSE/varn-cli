import { describe, expect, it } from "vitest";
import { Readable } from "node:stream";
import { MASK, Masker, maskingStream } from "../src/mask";

/** Feeds `text` to a masker in the given pieces and returns the output. */
function feed(values: string[], pieces: (string | Buffer)[]): string {
  const masker = new Masker(values);
  const out = pieces.map((p) => masker.push(typeof p === "string" ? Buffer.from(p) : p));
  out.push(masker.flush());
  return Buffer.concat(out).toString("utf8");
}

/** Every way of cutting `text` into two pieces, plus one byte at a time. */
function splits(text: string): Buffer[][] {
  const bytes = Buffer.from(text);
  const result: Buffer[][] = [];
  for (let i = 0; i <= bytes.length; i++) result.push([bytes.subarray(0, i), bytes.subarray(i)]);
  result.push([...bytes].map((b) => Buffer.from([b])));
  return result;
}

describe("Masker", () => {
  it("replaces every occurrence of a value", () => {
    expect(feed(["hunter2"], ["pw=hunter2 and again hunter2."])).toBe(`pw=${MASK} and again ${MASK}.`);
  });

  it("masks a value split at any point between chunks, including inside a multi-byte character", () => {
    const value = "pässwörd-€-🔑";
    const text = `before ${value} after`;
    for (const pieces of splits(text)) expect(feed([value], pieces)).toBe(`before ${MASK} after`);
  });

  it("masks the longest value when values overlap or one contains another", () => {
    expect(feed(["abc", "abcdef"], ["xabcdefx"])).toBe(`x${MASK}x`);
    for (const pieces of splits("xabcdefx")) expect(feed(["abc", "abcdef"], pieces)).toBe(`x${MASK}x`);
    // Overlapping different values become one masked span; no part of either leaks.
    for (const pieces of splits("1abcdef2")) expect(feed(["abcd", "cdef"], pieces)).toBe(`1${MASK}2`);
    // A value that continues one already seen at the end of a chunk.
    for (const pieces of splits("1abcde2")) expect(feed(["abc", "cde"], pieces)).toBe(`1${MASK}2`);
  });

  it("holds back only a tail that could start a value, and releases it when it does not", () => {
    const masker = new Masker(["secret"]);
    expect(masker.push(Buffer.from("plain text, no tail")).toString()).toBe("plain text, no tail");
    expect(masker.push(Buffer.from("tail sec")).toString()).toBe("tail ");
    expect(masker.push(Buffer.from("ond")).toString()).toBe("second");
    expect(masker.push(Buffer.from("x se")).toString()).toBe("x ");
    expect(masker.flush().toString()).toBe("se");
  });

  it("masks multi-line values and values with regex characters literally", () => {
    expect(feed(["line one\nline two"], ["a line one\nline two b"])).toBe(`a ${MASK} b`);
    expect(feed(["a.*b"], ["axxb a.*b"])).toBe(`axxb ${MASK}`);
  });

  it("passes data through untouched with no values, and ignores empty values", () => {
    expect(feed([], ["anything"])).toBe("anything");
    expect(feed([""], ["anything"])).toBe("anything");
  });

  it("works as a stream", async () => {
    const chunks = ["the key is sk_li", "ve_123", " ok\n"];
    const out: Buffer[] = [];
    for await (const c of Readable.from(chunks.map((c) => Buffer.from(c))).pipe(maskingStream(["sk_live_123"]))) out.push(c as Buffer);
    expect(Buffer.concat(out).toString()).toBe(`the key is ${MASK} ok\n`);
  });
});
