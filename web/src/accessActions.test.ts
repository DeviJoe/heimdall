import { expect, test } from "vitest";
import { accessAction } from "./accessActions";

test.each([
  ["/me/factor-policy", "PUT", { policy: "both" }],
  ["/me/totp/finish", "POST", { code: "123456" }],
  ["/me/passkey/begin", "POST", {}],
  ["/users/u/status", "POST", { status: "disabled" }],
  ["/users/u/status", "POST", { status: "deleted" }],
  ["/users/u", "PUT", { shell: "/bin/false" }],
  ["/users/u/linux-password", "PUT", { password: "never-display-this" }],
  ["/keys/key", "DELETE", undefined],
  ["/roles", "POST", { id: "r" }],
  ["/bindings/b", "DELETE", undefined],
  ["/user-groups/g/members/remove", "POST", { users: ["u"] }],
  ["/user-groups/g/bindings/b", "DELETE", undefined],
  ["/unix-groups/g/members", "POST", { remove: ["u"] }],
  ["/unix-assignments/a", "DELETE", undefined],
  ["/nodes/move", "POST", { nodes: ["n"] }],
  ["/nodes/n", "PUT", { disabled: true }],
  ["/security/labels", "POST", {}],
  ["/settings", "PUT", { require_sk: true }],
  ["/tokens/t", "DELETE", undefined],
  ["/tokens", "POST", {}],
  ["/join-tokens", "POST", {}],
  ["/nodes/n/recovery-token", "POST", {}],
  ["/users/u/status", "POST", { status: "active" }],
  ["/join-tokens/t", "PUT", {}],
  ["/announcements/message?version=1", "DELETE", undefined],
])("requires a consequence confirmation for %s %s", (path, method, body) => {
  const action = accessAction(path, method, body);
  expect(action?.message).toBeTruthy();
  expect(JSON.stringify(action)).not.toContain("never-display-this");
  expect(JSON.stringify(action)).not.toContain("123456");
});

test.each([
  ["/me", "GET", undefined],
  ["/auth/login", "POST", {}],
  ["/me/totp/begin", "POST", {}],
  ["/me/passkey/finish", "POST", {}],
  ["/roles", "POST", { name: "New role" }],
  ["/nodes/n/retry", "POST", {}],
  ["/incidents/i/resolve", "POST", {}],
])(
  "does not interrupt reads or harmless preparation for %s",
  (path, method, body) => {
    expect(accessAction(path, method, body)).toBeNull();
  },
);
