import { Chip, Tooltip } from "@mui/material";
import { FiberManualRecord } from "@mui/icons-material";
import type { Node } from "./types";
export function nodeHealth(
  node: Pick<Node, "health" | "disabled" | "connectivity" | "status">,
) {
  return (
    node.health ||
    (node.disabled
      ? "disabled"
      : node.connectivity === "offline"
        ? "offline"
        : node.connectivity === "online" && node.status === "in_sync"
          ? "healthy"
          : "warning")
  );
}
const labels: Record<string, string> = {
  healthy: "Синхронизирована",
  warning: "Нарушена синхронизация",
  offline: "Offline",
  disabled: "Отключена",
};
export function NodeHealth({
  node,
}: {
  node: Pick<Node, "health" | "disabled" | "connectivity" | "status">;
}) {
  const status = nodeHealth(node),
    color =
      status === "healthy"
        ? "success"
        : status === "warning"
          ? "warning"
          : "error";
  return (
    <Tooltip
      title={
        status === "offline"
          ? "Нет heartbeat агента. Уже применённый локальный доступ сохраняется."
          : labels[status]
      }
    >
      <Chip
        size="small"
        variant="outlined"
        color={color}
        icon={<FiberManualRecord sx={{ fontSize: "12px !important" }} />}
        label={labels[status] || status}
      />
    </Tooltip>
  );
}
