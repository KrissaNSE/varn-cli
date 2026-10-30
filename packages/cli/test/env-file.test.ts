import { describe, expect, it } from "vitest";
import { CliError, EXIT } from "../src/errors";
import { parseEnvFile } from "../src/env-file";

describe("parseEnvFile", () => {
  it("reads the usual .env forms", () => {
    const vars = parseEnvFile(
      [
        "﻿# comment",
        "",
        "PLAIN=value",
        "export EXPORTED=yes",
        "SPACED =  trimmed value  ",
        "COMMENTED=abc # a comment",
        "HASH=abc#not-a-comment",
        "SINGLE='keep \\n # as is'",
        'DOUBLE="a\\nb \\"q\\" # in quotes" # comment',
        "EMPTY=",
        "REF=varn://exempel/Produktion/Databas/password",
      ].join("\r\n"),
      ".env",
    );
    expect(Object.fromEntries(vars)).toEqual({
      PLAIN: "value",
      EXPORTED: "yes",
      SPACED: "trimmed value",
      COMMENTED: "abc",
      HASH: "abc#not-a-comment",
      SINGLE: "keep \\n # as is",
      DOUBLE: 'a\nb "q" # in quotes',
      EMPTY: "",
      REF: "varn://exempel/Produktion/Databas/password",
    });
  });

  it.each([
    ["no equals sign", "JUSTAKEY"],
    ["a bad name", "1ABC=x"],
    ["an unclosed quote", 'A="abc'],
    ["text after a quote", "A='abc' def"],
  ])("refuses %s, naming the line but not its content", (_, line) => {
    let error: unknown;
    try {
      parseEnvFile(`OK=1\n${line}`, "prod.env");
    } catch (e) {
      error = e;
    }
    expect(error).toBeInstanceOf(CliError);
    expect((error as CliError).exitCode).toBe(EXIT.io);
    expect((error as CliError).message).toContain("prod.env, line 2");
    expect((error as CliError).message).not.toContain(line);
  });
});
