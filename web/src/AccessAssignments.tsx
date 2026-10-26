import { useState } from "react";
import {
  Alert,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Paper,
  Stack,
  TableCell,
  TableRow,
  TextField,
  Typography,
} from "@mui/material";
import { Add, OpenInNew } from "@mui/icons-material";
import { api, can, canAny } from "./api";
import { DataTable } from "./common";
import { Pagination, useCollection } from "./Pagination";
import { ResourceSelect } from "./ResourceSelect";
import { useDebounced } from "./useDebounced";
import type { Me } from "./types";
type Assignment = {
  id: string;
  unix_group_id: string;
  group_id: string;
  role_id: string;
  unix_group_name: string;
  group_name: string;
  role_name: string;
};
export function AccessAssignments({
  me,
  act,
}: {
  me: Me;
  act: (fn: () => Promise<unknown>) => Promise<void>;
}) {
  const [query, setQuery] = useState(""),
    [version, setVersion] = useState(0),
    [open, setOpen] = useState(false),
    [unix, setUnix] = useState(""),
    [scope, setScope] = useState(""),
    [role, setRole] = useState("");
  const listing = useCollection<Assignment>(
    "/unix-assignments?query=" + encodeURIComponent(useDebounced(query)),
    version,
  );
  const graphAllowed = ["users.read", "roles.read", "nodes.read"].every((p) =>
    can(me, p),
  );
  return (
    <Stack gap={3}>
      <Stack
        direction={{ xs: "column", sm: "row" }}
        gap={2}
        justifyContent="space-between"
      >
        <Typography color="text.secondary">
          UNIX-группа → роль входа / sudo → группа нод. Доступ наследуется
          дочерними группами нод.
        </Typography>
        <Stack direction="row" gap={1}>
          {graphAllowed && (
            <Button
              href="/?page=access-graph"
              target="_blank"
              rel="noopener"
              endIcon={<OpenInNew />}
            >
              Граф доступов
            </Button>
          )}
          {can(me, "users.manage") &&
            canAny(me, "roles.manage") &&
            (can(me, "roles.read") || can(me, "roles.manage")) && (
              <Button
                variant="contained"
                startIcon={<Add />}
                onClick={() => {
                  setUnix("");
                  setScope("");
                  setRole("");
                  setOpen(true);
                }}
              >
                Назначить доступ
              </Button>
            )}
        </Stack>
      </Stack>
      <TextField
        label="Поиск: UNIX-группа, роль, группа нод"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
      />
      {listing.error && <Alert severity="error">{listing.error}</Alert>}
      <DataTable
        heads={["UNIX-группа", "Роль входа / sudo", "Группа нод", ""]}
        empty={!listing.items.length}
      >
        {listing.items.map((b) => (
          <TableRow key={b.id}>
            <TableCell>{b.unix_group_name}</TableCell>
            <TableCell>{b.role_name}</TableCell>
            <TableCell>{b.group_name}</TableCell>
            <TableCell>
              {can(me, "roles.manage", b.group_id) && (
                <Button
                  color="error"
                  onClick={() =>
                    void act(async () => {
                      await api(`/unix-assignments/${b.id}`, "DELETE");
                      setVersion((v) => v + 1);
                    })
                  }
                >
                  Отозвать
                </Button>
              )}
            </TableCell>
          </TableRow>
        ))}
      </DataTable>
      <Pagination {...listing} next={!!listing.next} />
      <Paper className="panel">
        <Typography variant="body2">
          Для входа нужны: активный пользователь, включённая синхронизация
          UNIX-учётки, членство в группе и разрешённый способ входа. Требования
          факторов и метки безопасности проверяются дополнительно.{" "}
          <a href="/?page=docs&doc=access-management">
            Порядок настройки и отзыва
          </a>
        </Typography>
      </Paper>
      <Dialog
        open={open}
        onClose={() => setOpen(false)}
        fullWidth
        maxWidth="sm"
      >
        <DialogTitle>Назначить доступ к нодам</DialogTitle>
        <DialogContent>
          <Stack gap={3} pt={1}>
            <ResourceSelect
              resource="/unix-groups"
              label="1. UNIX-группа пользователей"
              value={unix}
              onChange={setUnix}
            />
            <ResourceSelect
              resource="/roles?status=unix"
              label="2. Роль входа / sudo"
              value={role}
              onChange={setRole}
            />
            <ResourceSelect
              resource="/groups"
              label="3. Группа нод"
              value={scope}
              onChange={setScope}
            />
            <Typography variant="body2" color="text.secondary">
              Назначение распространяется на текущих и будущих участников
              UNIX-группы и на дочерние группы нод. Права Heimdall из этой роли
              через UNIX-группу не выдаются.
            </Typography>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpen(false)}>Отмена</Button>
          <Button
            variant="contained"
            disabled={
              !unix || !role || !scope || !can(me, "roles.manage", scope)
            }
            onClick={() =>
              void act(async () => {
                await api("/unix-assignments", "POST", {
                  unix_group_id: unix,
                  role_id: role,
                  group_id: scope,
                });
                setVersion((v) => v + 1);
                setOpen(false);
              })
            }
          >
            Назначить
          </Button>
        </DialogActions>
      </Dialog>
    </Stack>
  );
}
