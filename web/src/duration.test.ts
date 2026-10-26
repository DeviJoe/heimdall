import { expect, test } from "vitest";
import { durationSeconds, formatDuration } from "./duration";
test("join token lifetime accepts days and bounded durations", () => {
  expect(durationSeconds("365d")).toBe(31536000);
  expect(durationSeconds("60m")).toBe(3600);
  for (const text of ["-1d", "0d", "999999999999d", "1", "3651d"]) {
    expect(() => durationSeconds(text)).toThrow();
  }
});
test("policy durations preserve exact seconds and explicit zero", () => {
  for (const seconds of [0, 5, 15, 65, 3600, 86400, 31536000]) {
    expect(
      durationSeconds(formatDuration(seconds), { min: 0, max: 31536000 }),
    ).toBe(seconds);
  }
  expect(() => durationSeconds("0", { min: 5 })).toThrow();
  expect(() => durationSeconds("2h", { min: 5, max: 3600 })).toThrow();
});
