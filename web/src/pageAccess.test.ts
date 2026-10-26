import { expect, test } from "vitest";
import { effectivePage, pageAllowed } from "./pageAccess";
import { administrator } from "./test/fixtures";

test("native login grants do not expose synchronization or management", () => {
  const me = {
    ...administrator,
    principal: {
      ...administrator.principal,
      bindings: [
        {
          id: "b",
          user_id: "u",
          role_id: "r",
          group_id: "*",
          role: {
            id: "r",
            name: "UNIX operator",
            permissions: [],
            sudo: [],
            linux_access: true,
          },
        },
      ],
    },
  };
  expect(pageAllowed(me, "overview")).toBe(true);
  expect(pageAllowed(me, "sync")).toBe(false);
  expect(pageAllowed(me, "users")).toBe(false);
  expect(effectivePage(me, "sync")).toBe("overview");
});
test("a scoped operator can read synchronization while enrollment stays restricted", () => {
  const me = {
    ...administrator,
    principal: {
      ...administrator.principal,
      bindings: administrator.principal.bindings.map((b) => ({
        ...b,
        group_id: "group",
        role: { ...b.role, permissions: ["sync.read"] },
      })),
    },
  };
  expect(pageAllowed(me, "sync")).toBe(true);
  expect(
    pageAllowed(
      { ...me, principal: { ...me.principal, restricted: true } },
      "sync",
    ),
  ).toBe(false);
  expect(
    effectivePage(
      { ...me, principal: { ...me.principal, restricted: true } },
      "overview",
    ),
  ).toBe("account");
});
test("scoped access managers use assignments while role definitions require global read", () => {
  const me = {
    ...administrator,
    principal: {
      ...administrator.principal,
      bindings: [
        {
          ...administrator.principal.bindings[0],
          group_id: "*",
          role: {
            ...administrator.principal.bindings[0].role,
            permissions: ["users.read"],
          },
        },
        {
          ...administrator.principal.bindings[0],
          group_id: "production",
          role: {
            ...administrator.principal.bindings[0].role,
            permissions: ["roles.manage"],
          },
        },
      ],
    },
  };
  expect(pageAllowed(me, "roles")).toBe(false);
  expect(pageAllowed(me, "access-assignments")).toBe(true);
  expect(pageAllowed(me, "access-graph")).toBe(false);
});
