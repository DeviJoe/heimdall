import { expect, test } from "vitest";
import { rolePurpose, roleWithPurpose } from "./Roles";
import type { Role } from "./types";

const combined: Role = {
  id: "role", name: "Engineer", permissions: ["nodes.read"],
  linux_access: true, allow_password: true, allow_ssh_keys: true,
  sudo: [], sudoers: "ALL=(root) NOPASSWD: /usr/bin/id",
};
test("role purposes separate product administration and native access without granting a login method implicitly", () => {
  const product = roleWithPurpose(combined, "application");
  expect(rolePurpose(product)).toBe("application");
  expect(product.permissions).toEqual(["nodes.read"]);
  expect(product.allow_password).toBe(false);
  expect(product.allow_ssh_keys).toBe(false);
  expect(product.sudoers).toBe("");
  const native = roleWithPurpose(product, "unix");
  expect(rolePurpose(native)).toBe("unix");
  expect(native.permissions).toEqual([]);
  expect(native.linux_access).toBe(true);
  expect(native.allow_password).toBe(false);
  expect(native.allow_ssh_keys).toBe(false);
  expect(roleWithPurpose(combined, "combined")).toEqual(combined);
  expect(combined.permissions).toEqual(["nodes.read"]);
  expect(combined.sudoers).not.toBe("");
});
