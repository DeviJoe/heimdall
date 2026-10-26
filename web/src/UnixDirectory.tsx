import { useState } from "react";
import {
  Alert,
  Box,
  Button,
  Checkbox,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  List,
  ListItemButton,
  ListItemText,
  MenuItem,
  Paper,
  Stack,
  Tab,
  Tabs,
  TableCell,
  TableRow,
  TextField,
  Typography,
} from "@mui/material";
import { api, can } from "./api";
import { DataTable } from "./common";
import { Labels } from "./Labels";
import { Pagination, useCollection } from "./Pagination";
import type { Group, Me, Role, User } from "./types";
type UnixGroup = {
  id: string;
  name: string;
  gid: number;
  member_count: number;
  primary_count: number;
};
export function UnixDirectory({
  me,
  groups,
  act,
}: {
  me: Me;
  roles: Role[];
  groups: Group[];
  act: (fn: () => Promise<unknown>) => Promise<void>;
}) {
  const [tab, setTab] = useState("groups"),
    [groupSearch, setGroupSearch] = useState(""),
    [userSearch, setUserSearch] = useState(""),
    [id, setID] = useState(""),
    [membersOnly, setMembersOnly] = useState(true),
    [selected, setSelected] = useState<string[]>([]),
    [version, setVersion] = useState(0),
    [edit, setEdit] = useState<UnixGroup | null>(null),
    [remove, setRemove] = useState(false);
  const directory = useCollection<UnixGroup>(
      "/unix-groups?query=" + encodeURIComponent(groupSearch),
      version,
    ),
    listing = useCollection<User>(
      `/users?unix_group=${id}&members=${membersOnly}&query=${encodeURIComponent(userSearch)}`,
      version,
      tab === "groups" && !!id,
    );
  const group = directory.items.find((g) => g.id === id),
    checked = new Set(selected);
  async function changed(fn: () => Promise<unknown>) {
    await fn();
    setSelected([]);
    setVersion((v) => v + 1);
  }
  return (
    <Stack gap={3}>
      <Typography variant="body2">
        POSIX-группы ОС: имя, gidNumber, primary и supplementary членство. Вход
        и sudo назначаются в разделе «Доступ».{" "}
        <a href="/?page=docs&doc=access-management">Как назначить доступ</a>
      </Typography>
      <Tabs
        value={tab}
        onChange={(_, v) => setTab(v)}
        aria-label="UNIX-каталог"
      >
        <Tab value="groups" label="Группы UNIX" />
        {can(me, "security.manage") && (
          <Tab value="labels" label="Метки безопасности" />
        )}
      </Tabs>
      {tab === "groups" && (
        <>
          <Stack direction="row" justifyContent="flex-end">
            {can(me, "users.manage") && (
              <Button
                variant="contained"
                onClick={() =>
                  setEdit({
                    id: "",
                    name: "",
                    gid: 0,
                    member_count: 0,
                    primary_count: 0,
                  })
                }
              >
                Создать UNIX-группу
              </Button>
            )}
          </Stack>
          <Box
            sx={{
              display: "grid",
              gridTemplateColumns: { xs: "1fr", md: "280px minmax(0,1fr)" },
              gap: 3,
            }}
          >
            <Paper className="panel">
              <TextField
                fullWidth
                label="Поиск cn / gidNumber"
                value={groupSearch}
                onChange={(e) => setGroupSearch(e.target.value)}
              />
              {directory.error && (
                <Alert severity="error">{directory.error}</Alert>
              )}
              <List aria-label="Группы UNIX">
                {directory.items.map((g) => (
                  <ListItemButton
                    key={g.id}
                    selected={g.id === id}
                    onClick={() => {
                      setID(g.id);
                      setSelected([]);
                    }}
                  >
                    <ListItemText
                      primary={g.name}
                      secondary={`gidNumber=${g.gid}`}
                    />
                  </ListItemButton>
                ))}
              </List>
              <Pagination {...directory} next={!!directory.next} />
            </Paper>
            <Paper className="panel">
              <Stack gap={3}>
                {group ? (
                  <>
                    <Stack
                      direction="row"
                      alignItems="center"
                      justifyContent="space-between"
                    >
                      <Typography variant="h6">
                        {group.name} · posixGroup
                      </Typography>
                      {can(me, "users.manage") && (
                        <Button color="error" onClick={() => setRemove(true)}>
                          Удалить группу
                        </Button>
                      )}
                    </Stack>
                    <Stack direction="row" gap={1}>
                      <Chip label={`gidNumber=${group.gid}`} />
                      <Chip label={`Основная: ${group.primary_count}`} />
                      <Chip label={`Дополнительная: ${group.member_count}`} />
                    </Stack>
                    <Typography variant="body2">
                      Primary GID задаётся в UNIX-профиле пользователя.
                      Дополнительное членство — memberUid.
                    </Typography>
                    <Stack direction={{ xs: "column", sm: "row" }} gap={2}>
                      <TextField
                        label="Поиск логина или имени"
                        value={userSearch}
                        onChange={(e) => setUserSearch(e.target.value)}
                      />
                      <TextField
                        select
                        label="Пользователи"
                        value={String(membersOnly)}
                        onChange={(e) =>
                          setMembersOnly(e.target.value === "true")
                        }
                      >
                        <MenuItem value="true">Состав группы</MenuItem>
                        <MenuItem value="false">Все · для добавления</MenuItem>
                      </TextField>
                    </Stack>
                    {listing.error && (
                      <Alert severity="error">{listing.error}</Alert>
                    )}
                    <DataTable
                      heads={["", "uid / login", "UID", "Членство"]}
                      empty={!listing.items.length}
                    >
                      {listing.items.map((u) => (
                        <TableRow key={u.id}>
                          <TableCell>
                            <Checkbox
                              slotProps={{ input: { "aria-label": `Выбрать ${u.login}` } }}
                              disabled={
                                !can(me, "users.manage") || u.unix_primary
                              }
                              checked={checked.has(u.id)}
                              onChange={(_, v) =>
                                setSelected(
                                  v
                                    ? [...selected, u.id]
                                    : selected.filter((id) => id !== u.id),
                                )
                              }
                            />
                          </TableCell>
                          <TableCell>
                            {u.login} · {u.display_name}
                          </TableCell>
                          <TableCell>{u.uid}</TableCell>
                          <TableCell>
                            {u.unix_primary
                              ? "Основная"
                              : u.unix_member
                                ? "Дополнительная"
                                : "—"}
                          </TableCell>
                        </TableRow>
                      ))}
                    </DataTable>
                    <Pagination {...listing} next={!!listing.next} />
                    {can(me, "users.manage") && (
                      <Stack direction="row" gap={1} flexWrap="wrap">
                        <Button
                          disabled={!selected.length || selected.length > 500}
                          onClick={() =>
                            void act(() =>
                              changed(() =>
                                api(`/unix-groups/${id}/members`, "POST", {
                                  add: selected,
                                  remove: [],
                                }),
                              ),
                            )
                          }
                        >
                          Добавить выбранных ({selected.length})
                        </Button>
                        <Button
                          color="error"
                          disabled={!selected.length || selected.length > 500}
                          onClick={() =>
                            void act(() =>
                              changed(() =>
                                api(`/unix-groups/${id}/members`, "POST", {
                                  add: [],
                                  remove: selected,
                                }),
                              ),
                            )
                          }
                        >
                          Убрать выбранных
                        </Button>
                      </Stack>
                    )}
                  </>
                ) : (
                  <Typography color="text.secondary">
                    Выберите UNIX-группу.
                  </Typography>
                )}
              </Stack>
            </Paper>
          </Box>
        </>
      )}
      {tab === "labels" && can(me, "security.manage") && (
        <Labels me={me} groups={groups} act={act} />
      )}
      <Dialog
        open={!!edit}
        onClose={() => setEdit(null)}
        fullWidth
        maxWidth="sm"
      >
        <DialogTitle>Новая UNIX-группа</DialogTitle>
        <DialogContent>
          {edit && (
            <Stack gap={3} pt={1}>
              <TextField
                label="cn · UNIX-имя"
                value={edit.name}
                onChange={(e) => setEdit({ ...edit, name: e.target.value })}
              />
              <TextField
                label="gidNumber · 0 = автоматически"
                type="number"
                value={edit.gid}
                onChange={(e) =>
                  setEdit({ ...edit, gid: Number(e.target.value) })
                }
              />
              <Typography variant="body2">
                Имя и GID закрепляются за созданной группой. Для смены primary
                GID используется обслуживание UNIX-профиля.
              </Typography>
            </Stack>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEdit(null)}>Отмена</Button>
          <Button
            disabled={!edit?.name.trim()}
            onClick={() =>
              void act(() =>
                changed(async () => {
                  await api("/unix-groups", "POST", {
                    name: edit!.name,
                    gid: edit!.gid,
                    members: [],
                  });
                  setEdit(null);
                }),
              )
            }
          >
            Создать
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog open={remove} onClose={() => setRemove(false)}>
        <DialogTitle>Удалить {group?.name}?</DialogTitle>
        <DialogContent>
          Сначала снимите назначения доступа и перенесите пользователей, для
          которых это primary GID. Дополнительное членство удалится при
          синхронизации.
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRemove(false)}>Отмена</Button>
          <Button
            color="error"
            onClick={() =>
              void act(() =>
                changed(async () => {
                  await api(`/unix-groups/${id}`, "DELETE", undefined, {
                    confirmed: true,
                  });
                  setRemove(false);
                  setID("");
                }),
              )
            }
          >
            Удалить
          </Button>
        </DialogActions>
      </Dialog>
    </Stack>
  );
}
