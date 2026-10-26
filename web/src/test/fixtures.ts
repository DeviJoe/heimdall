import type { Me } from "../types";
export const administrator: Me = {
  user: { id: "admin", login: "admin", display_name: "Administrator", status: "active", uid: 10000, gid: 10000, home: "/home/admin", shell: "/bin/bash", gecos: "", require_mfa: false, mfa_enabled: false, source: "local" },
  principal: { user_id: "admin", login: "admin", restricted: false, bindings: [{id: "binding", user_id: "admin", role_id: "role", group_id: "*", role: { id: "role", name: "Administrator", permissions: ["*"], linux_access: false, sudo: [] }}] },
  permissions: ["roles.manage"], require_sk: false, key_ttl_seconds: 3600, telegram_enabled: false, mattermost_enabled: false, swagger_enabled: true, mcp_enabled: true,
};
