import { expect, test } from "vitest";
import { parseSudoRule, renderSudoRule } from "./SudoEditor";
test("builder preserves native wildcard and argument syntax", () => {
  const draft = {
    hosts: "ALL",
    runAs: "root:root",
    command: "/usr/bin/find",
    arguments: '-name "*.log"',
    noPassword: true,
  };
  expect(renderSudoRule(draft)).toBe(
    'ALL=(root:root) NOPASSWD: /usr/bin/find -name "*.log"',
  );
  expect(parseSudoRule(renderSudoRule(draft))).toEqual(draft);
});
test("empty arguments explicitly prohibit arguments instead of granting arbitrary ones", () => {
  const rule = {
    hosts: "ALL",
    runAs: "root",
    command: "/usr/bin/id",
    arguments: "",
    noPassword: false,
  };
  expect(renderSudoRule(rule)).toBe('ALL=(root) PASSWD: /usr/bin/id ""');
  expect(parseSudoRule(renderSudoRule(rule))).toEqual(rule);
});
test("complex native syntax remains in text editor instead of a lossy conversion", () => {
  expect(
    parseSudoRule("ALL=(ALL:ALL) NOPASSWD: /usr/bin/id, /usr/bin/whoami"),
  ).toBeNull();
  expect(parseSudoRule("ALL=(root) NOEXEC: /usr/bin/less *")).toBeNull();
});
