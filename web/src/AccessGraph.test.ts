import { expect, test } from "vitest";
import { graphLayout, type Connection } from "./AccessGraph";
const connection = (
  id: string,
  group: string,
  subject: string,
): Connection => ({
  id,
  subject_id: subject,
  subject_name: subject,
  subject_kind: "unix_group",
  group_id: group,
  group_name: group,
  ancestors: [group],
  role: {
    id: "shared-role",
    name: "Engineer",
    permissions: [],
    linux_access: true,
    allow_ssh_keys: true,
    sudo: [],
  },
});
test("shared role keeps scope-specific vertices; no fabricated cross-scope grant", () => {
  const g = graphLayout([
    connection("a", "production", "alice"),
    connection("b", "stage", "bob"),
  ]);
  const grants = g.vertices.filter((v) => v.column === 1);
  expect(grants).toHaveLength(2);
  for (const grant of grants) {
    const e = g.edges.find((e) => e.from === grant.id)!;
    expect(e.to).toBe(
      "scope:" + (grant.id.includes("production") ? "production" : "stage"),
    );
  }
});
test("shared edges retain every assignment for selection highlighting", () => {
  const g = graphLayout([
    connection("a", "production", "alice"),
    connection("b", "production", "bob"),
  ]);
  expect(g.edges.find((e) => e.to === "scope:production")?.connections).toEqual(
    ["a", "b"],
  );
});
