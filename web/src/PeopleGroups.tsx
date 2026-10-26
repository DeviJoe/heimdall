import { ResourceSelect } from "./ResourceSelect";
import { useEffect, useMemo, useState } from "react";
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
  FormControlLabel,
  List,
  ListItemButton,
  ListItemText,
  MenuItem,
  Paper,
  Stack,
  TableCell,
  TableRow,
  TextField,
  Typography,
} from "@mui/material";
import { api, can } from "./api";
import { Pagination, useCollection } from "./Pagination";
import { DataTable } from "./common";
import { factorPolicies } from "./factorPolicies";
import type { Binding, Group, Me, Role, User } from "./types";
type PeopleGroup = {
  id: string;
  name: string;
  mfa_policy: string;
  require_sk: boolean;
  members?: string[];
  member_count?: number;
  purpose: string;
  totp_count: number;
  passkey_count: number;
  missing_factors: number;
};
const blank: PeopleGroup = {
  id: "",
  name: "",
  mfa_policy: "none",
  require_sk: false,
  purpose: "general",
  totp_count: 0,
  passkey_count: 0,
  missing_factors: 0,
};
export function PeopleGroups({
  me,
  groups,
  act,
}: {
  me: Me;
  roles: Role[];
  groups: Group[];
  act: (fn: () => Promise<unknown>) => Promise<void>;
}) {
  const [transfer, setTransfer] = useState(false),
    [assignRole, setAssignRole] = useState(false);
  const [items, setItems] = useState<PeopleGroup[]>([]),
    [selected, setSelected] = useState(""),
    [edit, setEdit] = useState<PeopleGroup | null>(null),
    [search, setSearch] = useState(""),
    [groupSearch, setGroupSearch] = useState(""),
    [factor, setFactor] = useState(""),
    [version, setVersion] = useState(0),
    [remove, setRemove] = useState(false),
    [filter, setFilter] = useState("members"),
    [users, setUsers] = useState<string[]>([]),
    [target, setTarget] = useState(""),
    [role, setRole] = useState(""),
    [scope, setScope] = useState("*"),
    [error, setError] = useState("");
  const directory = useCollection<PeopleGroup>(
    "/user-groups?query=" + encodeURIComponent(groupSearch),
    version,
  );
  const group = directory.items.find((g) => g.id === selected);
  const checked = useMemo(() => new Set(users), [users]);
  async function load() {
    await directory.reload();
    setVersion((v) => v + 1);
    setError("");
  }
  const bindingList = useCollection<Binding>(
    `/user-groups/${selected}/bindings`,
    version,
    !!selected,
  );
  const bindings = bindingList.items;
  const loadBindings = bindingList.reload;
  useEffect(() => {
    setItems(directory.items);
  }, [directory.items]);
  useEffect(() => {
    setUsers([]);
  }, [selected]);
  const listing = useCollection<User>(
    `/users?kind=human&query=${encodeURIComponent(search)}&people_group=${filter === "members" ? selected : ""}&factor=${factor}`,
    version,
    !!selected,
  );
  const visible = listing.items;
  return (
    <Stack gap={3}>
      {error && <Alert severity="error">{error}</Alert>}
      <Stack direction="row" justifyContent="flex-end">
        {can(me, "users.manage") && (
          <Button variant="contained" onClick={() => setEdit({ ...blank })}>
            Создать группу людей
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
        <Paper className="panel" sx={{ p: 1 }}>
          <TextField
            fullWidth
            label="Поиск групп людей"
            value={groupSearch}
            onChange={(e) => setGroupSearch(e.target.value)}
          />
          {directory.error && <Alert severity="error">{directory.error}</Alert>}
          <List aria-label="Группы людей">
            {items.map((g) => (
              <ListItemButton
                key={g.id}
                selected={g.id === selected}
                onClick={() => setSelected(g.id)}
                sx={{ borderRadius: 2 }}
              >
                <ListItemText
                  primary={g.name}
                  secondary={`${g.member_count ?? g.members?.length ?? 0} пользователей · ${factorPolicies[g.mfa_policy as keyof typeof factorPolicies]}`}
                />
              </ListItemButton>
            ))}
          </List>
          <Pagination {...directory} next={!!directory.next} />
        </Paper>
        <Paper className="panel">
          <Stack gap={3}>
            {!group ? (
              <Typography>Выберите группу</Typography>
            ) : (
              <>
                <Stack
                  direction="row"
                  alignItems="center"
                  justifyContent="space-between"
                >
                  <Typography variant="h6">{group.name}</Typography>
                  {can(me, "users.manage") && (
                    <Button onClick={() => setEdit({ ...group })}>
                      Настроить группу
                    </Button>
                  )}
                  <Button
                    color="error"
                    onClick={() => setRemove(true)}
                    disabled={!can(me, "users.manage")}
                  >
                    Удалить группу
                  </Button>
                </Stack>
                <Stack direction="row" gap={1} flexWrap="wrap">
                  <Chip label={`TOTP: ${group.totp_count}`} />
                  <Chip label={`Passkey: ${group.passkey_count}`} />
                  <Chip
                    label={`Не выполнили политику: ${group.missing_factors}`}
                    color={group.missing_factors ? "warning" : "default"}
                  />
                  {group.require_sk && <Chip label="Только SSH sk" />}
                </Stack>
                <Stack direction={{ xs: "column", sm: "row" }} gap={2}>
                  <TextField
                    label="Поиск по логину или имени"
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                  />
                  <TextField
                    select
                    label="Пользователи"
                    value={filter}
                    onChange={(e) => setFilter(e.target.value)}
                  >
                    <MenuItem value="members">Состав группы</MenuItem>
                    <MenuItem value="all">
                      Все люди · для переноса / добавления
                    </MenuItem>
                  </TextField>
                  <TextField
                    select
                    label="Факторы"
                    value={factor}
                    onChange={(e) => setFactor(e.target.value)}
                  >
                    <MenuItem value="">Все</MenuItem>
                    <MenuItem value="totp">Включён TOTP</MenuItem>
                    <MenuItem value="passkey">Есть Passkey</MenuItem>
                    <MenuItem value="none">Нет факторов</MenuItem>
                    <MenuItem value="missing">Не выполнили политику</MenuItem>
                  </TextField>
                </Stack>
                {listing.error && (
                  <Alert severity="error">{listing.error}</Alert>
                )}
                <DataTable
                  heads={["", "Пользователь", "TOTP", "Passkeys"]}
                  empty={!visible.length}
                >
                  {visible.map((u) => (
                    <TableRow key={u.id}>
                      <TableCell>
                        <Checkbox
                          slotProps={{ input: { "aria-label": `Выбрать ${u.login}` } }}
                          checked={checked.has(u.id)}
                          disabled={!can(me, "users.manage")}
                          onChange={(_, value) =>
                            setUsers(
                              value
                                ? [...users, u.id]
                                : users.filter((id) => id !== u.id),
                            )
                          }
                        />
                      </TableCell>
                      <TableCell>
                        {u.login} · {u.display_name}
                        {filter === "members" && (
                          <Chip size="small" label="В группе" sx={{ ml: 1 }} />
                        )}
                      </TableCell>
                      <TableCell>{u.totp_enabled ? "Включён" : "—"}</TableCell>
                      <TableCell>{u.passkey_count || 0}</TableCell>
                    </TableRow>
                  ))}
                </DataTable>
                <Pagination {...listing} next={!!listing.next} />
                {can(me, "users.manage") && users.length > 0 && (
                  <Stack direction="row" gap={1} flexWrap="wrap">
                    <Button
                      variant="contained"
                      onClick={() => setTransfer(true)}
                    >
                      Переместить ({users.length})
                    </Button>
                    {filter === "all" && (
                      <Button
                        onClick={() =>
                          void act(async () => {
                            await api("/user-groups/move", "POST", {
                              source: "",
                              target: selected,
                              users,
                            });
                            setUsers([]);
                            await load();
                          })
                        }
                      >
                        Добавить в эту группу
                      </Button>
                    )}
                    {filter === "members" && (
                      <Button
                        color="error"
                        onClick={() =>
                          void act(async () => {
                            await api(
                              `/user-groups/${selected}/members/remove`,
                              "POST",
                              { users },
                            );
                            setUsers([]);
                            await load();
                          })
                        }
                      >
                        Убрать из группы
                      </Button>
                    )}
                  </Stack>
                )}
                <Typography variant="h6">Роли группы людей</Typography>
                <Typography variant="body2" color="text.secondary">
                  Права управления Heimdall назначайте здесь. Для UNIX-доступа
                  используйте <a href="/?page=unix">UNIX-каталог</a>.
                </Typography>
                {bindings.map((b) => (
                  <Stack key={b.id} direction="row" gap={1} alignItems="center">
                    <Typography sx={{ flex: 1 }}>
                      {b.role.name} →{" "}
                      {b.group_id === "*"
                        ? "Все группы нод"
                        : b.group_name ||
                          groups.find((g) => g.id === b.group_id)?.name ||
                          b.group_id}
                    </Typography>
                    {can(me, "roles.manage", b.group_id) && (
                      <Button
                        color="error"
                        onClick={() =>
                          void act(async () => {
                            await api(
                              `/user-groups/${selected}/bindings/${b.id}`,
                              "DELETE",
                            );
                            await loadBindings();
                          })
                        }
                      >
                        Снять роль
                      </Button>
                    )}
                  </Stack>
                ))}
                {bindingList.error && (
                  <Alert severity="error">{bindingList.error}</Alert>
                )}
                <Pagination {...bindingList} next={!!bindingList.next} />
                {can(me, "roles.manage") && (
                  <Button onClick={() => setAssignRole(true)}>
                    Назначить роль
                  </Button>
                )}
              </>
            )}
          </Stack>
        </Paper>
      </Box>
      <Dialog
        open={transfer}
        onClose={() => setTransfer(false)}
        fullWidth
        maxWidth="sm"
      >
        <DialogTitle>Переместить людей · {users.length}</DialogTitle>
        <DialogContent>
          <Stack gap={3} pt={1}>
            <Typography color="text.secondary">
              {filter === "members"
                ? `Из группы ${group?.name}`
                : "Выбор из каталога людей"}
            </Typography>
            <ResourceSelect
              resource="/user-groups"
              label="Переместить в группу"
              value={target}
              onChange={setTarget}
            />
            <Typography variant="body2">
              Перемещение между группами факторов заменяет предыдущую группу
              факторов. Политики остальных групп и пользователя продолжают
              действовать.
            </Typography>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setTransfer(false)}>Отмена</Button>
          <Button
            disabled={
              !target ||
              target === selected ||
              !users.length ||
              users.length > 500
            }
            onClick={() =>
              void act(async () => {
                await api("/user-groups/move", "POST", {
                  source: filter === "members" ? selected : "",
                  target,
                  users,
                });
                setUsers([]);
                setTransfer(false);
                await load();
              })
            }
          >
            Переместить
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog
        open={assignRole}
        onClose={() => setAssignRole(false)}
        fullWidth
        maxWidth="sm"
      >
        <DialogTitle>Назначить роль группе · {group?.name}</DialogTitle>
        <DialogContent>
          <Stack gap={3} pt={1}>
            <ResourceSelect
              resource="/roles"
              label="Роль"
              value={role}
              onChange={setRole}
            />
            <ResourceSelect
              resource="/groups"
              label="Область роли"
              value={scope}
              onChange={setScope}
              initialLabel="Все группы нод"
              extraOptions={[{ id: "*", name: "Все группы нод" }]}
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setAssignRole(false)}>Отмена</Button>
          <Button
            disabled={!role}
            onClick={() =>
              void act(async () => {
                await api(`/user-groups/${selected}/bindings`, "POST", {
                  role_id: role,
                  group_id: scope,
                });
                setAssignRole(false);
                await loadBindings();
              })
            }
          >
            Назначить
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog open={remove} onClose={() => setRemove(false)}>
        <DialogTitle>Удалить {group?.name}?</DialogTitle>
        <DialogContent>
          Членство и назначения ролей группы будут удалены. Доступ
          пересчитывается по оставшимся назначениям.
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRemove(false)}>Отмена</Button>
          <Button
            color="error"
            onClick={() =>
              void act(async () => {
                await api(`/user-groups/${selected}`, "DELETE", undefined, {
                  confirmed: true,
                });
                setSelected("");
                setRemove(false);
                await load();
              })
            }
          >
            Удалить
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog
        open={!!edit}
        onClose={() => setEdit(null)}
        fullWidth
        maxWidth="sm"
      >
        <DialogTitle>Настройки группы людей</DialogTitle>
        <DialogContent>
          {edit && (
            <Stack gap={3} pt={1}>
              <TextField
                label="Название группы"
                value={edit.name}
                onChange={(e) => setEdit({ ...edit, name: e.target.value })}
              />
              <TextField
                select
                label="Обязательная регистрация факторов"
                value={edit.mfa_policy}
                onChange={(e) =>
                  setEdit({ ...edit, mfa_policy: e.target.value })
                }
              >
                {Object.entries(factorPolicies).map(([k, v]) => (
                  <MenuItem key={k} value={k}>
                    {v}
                  </MenuItem>
                ))}
              </TextField>
              <FormControlLabel
                label="Разрешены только SSH sk-ключи"
                control={
                  <Checkbox
                    checked={edit.require_sk}
                    onChange={(_, value) =>
                      setEdit({ ...edit, require_sk: value })
                    }
                  />
                }
              />
            </Stack>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEdit(null)}>Отмена</Button>
          <Button
            disabled={!edit?.name.trim()}
            onClick={() =>
              void act(async () => {
                await api("/user-groups", "POST", edit);
                setEdit(null);
                await load();
              })
            }
          >
            Сохранить
          </Button>
        </DialogActions>
      </Dialog>
    </Stack>
  );
}
