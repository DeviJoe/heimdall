import { Tab, Tabs } from "@mui/material";
import { OpenInNew } from "@mui/icons-material";
import { can } from "./api";
import type { Me } from "./types";
import { pageAllowed } from "./pageAccess";
export function AccessNavigation({ me, page }: { me: Me; page: string }) {
  const graphAllowed = ["users.read", "roles.read", "nodes.read"].every((p) =>
    can(me, p),
  );
  return (
    <Tabs
      value={page}
      aria-label="Управление доступом"
      sx={{ mb: 3 }}
      variant="scrollable"
    >
      {pageAllowed(me, "roles") && (
        <Tab value="roles" label="Роли" component="a" href="/?page=roles" />
      )}
      {pageAllowed(me, "access-assignments") && (
        <Tab
          value="access-assignments"
          label="Назначения на ноды"
          component="a"
          href="/?page=access-assignments"
        />
      )}
      {graphAllowed && (
        <Tab
          value="access-graph"
          label="Граф доступов"
          icon={<OpenInNew fontSize="small" />}
          iconPosition="end"
          component="a"
          href="/?page=access-graph"
          target={page === "access-graph" ? undefined : "_blank"}
          rel="noopener"
        />
      )}
    </Tabs>
  );
}
