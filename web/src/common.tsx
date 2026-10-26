import {
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from "@mui/material";
import type { ReactNode } from "react";
const names: Record<string, string> = {
  in_sync: "Синхронизировано",
  applied: "Применено",
  pending: "Ожидает",
  succeeded: "Выполнено",
  failed: "Ошибка",
  online: "На связи",
  suspect: "Нет heartbeat",
  offline: "Не на связи",
  active: "Активен",
  disabled: "Заблокирован",
  disconnected: "Отключена от CP",
  deleted: "Удалён",
  invited: "Приглашён",
  revoked: "Отозван",
  expired: "Истёк",
  exhausted: "Лимит достигнут",
  open: "Открыт",
  acknowledged: "Принят",
  resolved: "Устранён",
  critical: "Критический",
  warning: "Предупреждение",
};
export function Status({ value }: { value: string }) {
  const good = [
      "in_sync",
      "applied",
      "succeeded",
      "active",
      "online",
      "resolved",
    ].includes(value),
    bad = [
      "failed",
      "disabled",
      "deleted",
      "revoked",
      "expired",
      "critical",
      "offline",
      "open",
    ].includes(value);
  return (
    <Chip
      label={names[value] || value}
      size="small"
      color={good ? "success" : bad ? "error" : "default"}
      variant="outlined"
    />
  );
}
export function DataTable({
  heads,
  children,
  empty,
}: {
  heads: string[];
  children: ReactNode;
  empty?: boolean;
}) {
  return (
    <TableContainer className="table-panel">
      <Table size="small">
        <TableHead>
          <TableRow>
            {heads.map((h) => (
              <TableCell key={h}>{h}</TableCell>
            ))}
          </TableRow>
        </TableHead>
        <TableBody>
          {empty ? (
            <TableRow>
              <TableCell colSpan={heads.length}>
                <Typography className="empty">Пока нет данных</Typography>
              </TableCell>
            </TableRow>
          ) : (
            children
          )}
        </TableBody>
      </Table>
    </TableContainer>
  );
}
