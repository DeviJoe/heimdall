import { useDebounced } from "./useDebounced";
import { useEffect, useState } from "react";
import {
  Alert,
  Button,
  Checkbox,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControlLabel,
  Paper,
  Stack,
  TableCell,
  TableRow,
  TextField,
  Typography,
} from "@mui/material";
import { api, can, date } from "./api";
import { durationSeconds } from "./duration";
import { DataTable, Status } from "./common";
import { Pagination, useCollection } from "./Pagination";
import type { Group, Me } from "./types";
type JoinToken = {
  name: string;
  id: string;
  group_id: string;
  group_name: string;
  uses: number;
  max_uses: number;
  expires_at: string;
  revoked_at: string | null;
};
export function JoinTokens({
  me,
  groups,
  act,
}: {
  me: Me;
  groups: Group[];
  act: (fn: () => Promise<unknown>) => Promise<void>;
}) {
  const [version, setVersion] = useState(0),
    [search, setSearch] = useState(""),
    [edit, setEdit] = useState<JoinToken | null>(null),
    [ttl, setTTL] = useState("365d"),
    [changeExpiry, setChangeExpiry] = useState(false),
    [unlimited, setUnlimited] = useState(true);
  const query = useDebounced(search);
  const listing = useCollection<JoinToken>(
      "/join-tokens?query=" + encodeURIComponent(query),
      version,
    ),
    names = new Map(groups.map((g) => [g.id, g.name]));
  useEffect(() => {
    const expiration = Math.min(
      ...listing.items.map((t) => Date.parse(t.expires_at)),
    );
    if (!Number.isFinite(expiration)) return;
    const timer = setTimeout(
      () => setVersion((v) => v + 1),
      Math.min(2147483647, Math.max(1000, expiration - Date.now() + 50)),
    );
    return () => clearTimeout(timer);
  }, [listing.items]);
  return (
    <Paper className="panel">
      <TextField
        label="Поиск токенов: название или группа нод"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        fullWidth
        sx={{ mb: 2 }}
      />
      {listing.error && <Alert severity="error">{listing.error}</Alert>}
      <DataTable
        heads={[
          "Название",
          "Группа нод",
          "Использования",
          "Действует до",
          "Статус",
          "",
        ]}
        empty={!listing.items.length}
      >
        {listing.items.map((t) => (
          <TableRow key={t.id}>
            <TableCell>{t.name || "Без названия"}</TableCell>
            <TableCell>
              {t.group_name || names.get(t.group_id) || t.group_id}
            </TableCell>
            <TableCell>
              {t.uses} / {t.max_uses === 0 ? "∞" : t.max_uses}
            </TableCell>
            <TableCell>{date(t.expires_at)}</TableCell>
            <TableCell>
              <Status
                value={
                  t.revoked_at
                    ? "revoked"
                    : t.max_uses > 0 && t.uses >= t.max_uses
                      ? "exhausted"
                      : "active"
                }
              />
            </TableCell>
            <TableCell>
              {!t.revoked_at && can(me, "nodes.manage", t.group_id) && (
                <Stack direction="row">
                  <Button
                    onClick={() => {
                      setEdit({ ...t });
                      setUnlimited(t.max_uses === 0);
                      setChangeExpiry(false);
                      setTTL("365d");
                    }}
                  >
                    Настроить
                  </Button>
                  <Button
                    color="error"
                    onClick={() =>
                      void act(async () => {
                        await api("/join-tokens/" + t.id, "DELETE");
                        setVersion((v) => v + 1);
                      })
                    }
                  >
                    Отозвать
                  </Button>
                </Stack>
              )}
            </TableCell>
          </TableRow>
        ))}
      </DataTable>
      <Pagination {...listing} next={!!listing.next} />
      <Dialog
        open={!!edit}
        onClose={() => setEdit(null)}
        fullWidth
        maxWidth="sm"
      >
        <DialogTitle>Настроить join-токен</DialogTitle>
        <DialogContent>
          {edit && (
            <Stack gap={3} pt={1}>
              <Typography>Использован {edit.uses} раз</Typography>
              <Typography>Действует до: {date(edit.expires_at)}</Typography>
              <FormControlLabel
                label="Без лимита присоединений"
                control={
                  <Checkbox
                    checked={unlimited}
                    onChange={(_, v) => setUnlimited(v)}
                  />
                }
              />
              <TextField
                type="number"
                label="Общее число присоединений"
                disabled={unlimited}
                value={edit.max_uses || 100}
                onChange={(e) =>
                  setEdit({ ...edit, max_uses: Number(e.target.value) })
                }
              />
              <FormControlLabel
                label="Изменить срок действия"
                control={
                  <Checkbox
                    checked={changeExpiry}
                    onChange={(_, v) => setChangeExpiry(v)}
                  />
                }
              />
              <TextField
                label="Срок жизни от момента сохранения"
                value={ttl}
                disabled={!changeExpiry}
                onChange={(e) => setTTL(e.target.value)}
                helperText="Например: 24h, 365d"
              />
            </Stack>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEdit(null)}>Отмена</Button>
          <Button
            onClick={() =>
              void act(async () => {
                await api(`/join-tokens/${edit!.id}`, "PUT", {
                  max_uses: unlimited ? 0 : edit!.max_uses || 100,
                  expires_at: changeExpiry
                    ? new Date(
                        Date.now() + durationSeconds(ttl) * 1000,
                      ).toISOString()
                    : edit!.expires_at,
                });
                setEdit(null);
                setVersion((v) => v + 1);
              })
            }
          >
            Сохранить
          </Button>
        </DialogActions>
      </Dialog>
    </Paper>
  );
}
