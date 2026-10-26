import { expect, test } from "vitest";
import { groupIncidents } from "./Incidents";
import type { Incident } from "./types";
const event: Incident = {
  id: "a",
  kind: "failed_authentication",
  node_id: "node-a",
  severity: "warning",
  message: "user guest from 192.0.2.10",
  status: "open",
  created_at: "2026-10-05T10:00:00Z",
};
test("repeated events are summarized without merging different hosts or hiding critical incidents", () => {
  const grouped = groupIncidents([
    event,
    { ...event, id: "b", occurrences: 5, last_seen: "2026-10-05T10:05:00Z" },
    { ...event, id: "c", node_id: "node-b" },
    { ...event, id: "d", severity: "critical", kind: "revocation_pending" },
    { ...event, id: "e", status: "resolved" },
  ]);
  expect(grouped).toHaveLength(3);
  expect(grouped[0].critical).toBe(true);
  const repeats = grouped.find((g) => g.items.length === 2)!;
  expect(repeats.count).toBe(6);
  expect(repeats.last).toBe("2026-10-05T10:05:00Z");
});
