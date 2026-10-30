/**
 * Output masking for `varn run`: every occurrence of a secret value in the
 * command's stdout/stderr is replaced with `<varn:concealed>`, also when the
 * command writes a value in several pieces.
 *
 * Works on bytes (the values' UTF-8 encoding), so a multi-byte character split
 * between two chunks is no problem. Only exact values are masked, not other
 * encodings of them (base64, URL-encoded, …).
 *
 * Correctness across chunks: a value that may continue in the next chunk can
 * only start in the tail of the data seen so far where the tail is a proper
 * prefix of some value. That tail is held back until more data arrives or the
 * stream ends; everything before it is final. Overlapping occurrences of
 * different values are merged into one masked span, and a span that reaches
 * into the held-back tail is held back with it, so a later overlap still
 * extends it. At most (longest value − 1) bytes plus such a span are held.
 */
import { Transform, type TransformCallback } from "node:stream";

export const MASK = "<varn:concealed>";
const MASK_BYTES = Buffer.from(MASK, "utf8");

export class Masker {
  private readonly secrets: Buffer[];
  private carry: Buffer = Buffer.alloc(0);

  constructor(values: Iterable<string>) {
    const unique = [...new Set([...values].filter((v) => v.length > 0))];
    this.secrets = unique.map((v) => Buffer.from(v, "utf8")).sort((a, b) => b.length - a.length);
  }

  get active(): boolean {
    return this.secrets.length > 0;
  }

  /** Feeds a chunk; returns what is safe to output now. */
  push(chunk: Buffer): Buffer {
    return this.process(Buffer.concat([this.carry, chunk]), false);
  }

  /** Ends the stream; returns the rest. */
  flush(): Buffer {
    return this.process(this.carry, true);
  }

  private process(data: Buffer, final: boolean): Buffer {
    if (!this.active) {
      this.carry = Buffer.alloc(0);
      return data;
    }
    // Every complete occurrence of every value, merged into disjoint spans.
    const spans: [number, number][] = [];
    for (const secret of this.secrets) {
      for (let at = data.indexOf(secret); at !== -1; at = data.indexOf(secret, at + 1)) spans.push([at, at + secret.length]);
    }
    spans.sort((a, b) => a[0] - b[0] || b[1] - a[1]);
    const merged: [number, number][] = [];
    for (const span of spans) {
      const last = merged[merged.length - 1];
      if (last && span[0] < last[1]) last[1] = Math.max(last[1], span[1]);
      else merged.push([span[0], span[1]]);
    }

    let cut = final ? data.length : this.holdFrom(data);
    for (const [start, end] of merged) {
      if (end > cut && start < cut) {
        cut = start;
        break;
      }
    }

    const out: Buffer[] = [];
    let from = 0;
    for (const [start, end] of merged) {
      if (end > cut) break;
      out.push(data.subarray(from, start), MASK_BYTES);
      from = end;
    }
    out.push(data.subarray(from, cut));
    this.carry = Buffer.from(data.subarray(cut));
    return Buffer.concat(out);
  }

  /** Earliest position whose suffix is a proper prefix of some value (data.length if none). */
  private holdFrom(data: Buffer): number {
    const longest = this.secrets[0]!.length;
    for (let q = Math.max(0, data.length - longest + 1); q < data.length; q++) {
      const tail = data.subarray(q);
      for (const secret of this.secrets) {
        if (secret.length > tail.length && secret[0] === tail[0] && secret.subarray(0, tail.length).equals(tail)) return q;
      }
    }
    return data.length;
  }
}

/** A Transform stream that masks `values`. */
export function maskingStream(values: Iterable<string>): Transform {
  const masker = new Masker(values);
  return new Transform({
    transform(chunk: Buffer | string, _encoding: BufferEncoding, callback: TransformCallback) {
      const out = masker.push(typeof chunk === "string" ? Buffer.from(chunk, "utf8") : chunk);
      callback(null, out.length > 0 ? out : undefined);
    },
    flush(callback: TransformCallback) {
      const out = masker.flush();
      callback(null, out.length > 0 ? out : undefined);
    },
  });
}
