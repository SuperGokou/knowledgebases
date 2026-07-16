import { describe, expect, test } from "vitest";

import { parseRfc4180Csv } from "../e2e/support/audit-csv";

describe("enterprise audit RFC 4180 parser", () => {
  test("parses commas, escaped quotes, empty fields, and quoted CRLF", () => {
    expect(
      parseRfc4180Csv(
        'id,action,note,empty\r\n1,audit.exported,"hello, ""world""",\r\n2,denied,"line one\r\nline two",x\r\n',
      ),
    ).toEqual([
      ["id", "action", "note", "empty"],
      ["1", "audit.exported", 'hello, "world"', ""],
      ["2", "denied", "line one\r\nline two", "x"],
    ]);
  });

  test("accepts a final record without CRLF and does not invent an empty trailing row", () => {
    expect(parseRfc4180Csv("a,b\r\n1,2")).toEqual([
      ["a", "b"],
      ["1", "2"],
    ]);
    expect(parseRfc4180Csv("a,b\r\n")).toEqual([["a", "b"]]);
  });

  test.each([
    ["a,b\n1,2", "bare LF"],
    ['a,"unterminated', "unterminated quoted field"],
    ['a,"closed"suffix\r\n', "characters after a closing quote"],
    ["a,invalid\"quote\r\n", "invalid quote"],
    ["a,b\r1,2", "CRLF"],
  ])("rejects malformed input %#", (source, message) => {
    expect(() => parseRfc4180Csv(source)).toThrow(message);
  });
});
