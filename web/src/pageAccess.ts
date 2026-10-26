import { can, canAny } from "./api";
import type { Me } from "./types";
export function pageAllowed(me: Me, page: string) {
  if (page === "docs") return true;
  if (page === "join-tokens") return canAny(me, "nodes.manage");
  if (me.principal.restricted) return page === "account";
  if (page === "access-graph")
    return ["roles.read", "users.read", "nodes.read"].every((p) => can(me, p));
  if (page === "access-assignments")
    return (
      can(me, "users.read") &&
      (canAny(me, "roles.read") || canAny(me, "roles.manage"))
    );
  if (["overview", "account", "nodes", "tokens"].includes(page)) return true;
  if (["users", "people-groups", "unix"].includes(page))
    return canAny(me, "users.read");
  if (page === "roles") return can(me, "roles.read") || can(me, "roles.manage");
  if (page === "sync") return canAny(me, "sync.read");
  if (page === "audit") return canAny(me, "audit.read");
  if (page === "settings") return canAny(me, "settings.manage");
  return false;
}
export function effectivePage(me: Me, requested: string) {
  return pageAllowed(me, requested)
    ? requested
    : me.principal.restricted
      ? "account"
      : "overview";
}
