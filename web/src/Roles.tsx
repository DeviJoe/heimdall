import { useState } from "react";
import {
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Alert,
  Button,
  Checkbox,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControlLabel,
  MenuItem,
  Paper,
  Stack,
  Tab,
  Tabs,
  TextField,
  Typography,
} from "@mui/material";
import { Add, ExpandMore, SecurityOutlined } from "@mui/icons-material";
import { SudoEditor } from "./SudoEditor";
import { api, can } from "./api";
import type { Group, Me, Role, User } from "./types";

const resources: Record<string, string> = {
  users: "Пользователи и группы",
  roles: "Роли и назначения",
  nodes: "Ноды",
  sync: "Синхронизация",
  sudo: "sudoers",
  tokens: "API-токены",
  integrations: "Интеграции",
  incidents: "Инциденты",
  audit: "Аудит",
  api_docs: "Swagger",
  inventory: "Ansible inventory",
  settings: "Настройки",
  security: "События и метки безопасности",
  announcements: "Сообщения в обзоре",
  documentation: "Документация",
};
const actions: Record<string, string> = {
  read: "Чтение",
  manage: "Управление",
  retry: "Повтор доставки",
};
function permissionName(p: string) {
  if (p === "*") return "Все права администратора";
  const [resource, action] = p.split(".");
  return `${resources[resource] || resource}: ${actions[action] || action}`;
}
export function normalizeRole(role: Role): Role {
  return {
    ...role,
    permissions: role.permissions ?? [],
    sudo: (role.sudo ?? []).map((s) => ({
      ...s,
      arguments: s.arguments ?? [],
    })),
    allow_password: role.allow_password ?? false,
    allow_ssh_keys: role.allow_ssh_keys ?? false,
  };
}
export type RolePurpose = "application" | "unix" | "combined";
export function rolePurpose(role: Role): RolePurpose {
  return role.linux_access
    ? (role.permissions ?? []).length ? "combined" : "unix"
    : "application";
}
export function roleWithPurpose(role: Role, purpose: RolePurpose): Role {
  const normalized = normalizeRole(role);
  return {
    ...normalized,
    permissions: purpose === "unix" ? [] : normalized.permissions,
    linux_access: purpose !== "application",
    allow_password: purpose === "application" ? false : normalized.allow_password,
    allow_ssh_keys: purpose === "application" ? false : normalized.allow_ssh_keys,
    sudo: purpose === "application" ? [] : normalized.sudo,
    sudoers: purpose === "application" ? "" : normalized.sudoers,
  };
}
const blank: Role = {
  id: "",
  name: "",
  permissions: [],
  linux_access: false,
  allow_password: false,
  allow_ssh_keys: false,
  sudo: [],
};
export function Roles({
  me,
  roles,
  act,
  kind = "all",
  onKindChange,
}: {
  me: Me;
  roles: Role[];
  groups: Group[];
  users: User[];
  act: (fn: () => Promise<unknown>) => Promise<void>;
  kind?: string;
  onKindChange?: (kind: string) => void;
}) {
  const [sudoPending, setSudoPending] = useState(false),
    [edit, setEdit] = useState<Role | null>(null),
    [remove, setRemove] = useState<Role | null>(null),
    [purpose, setPurpose] = useState<RolePurpose>("application"),
    [tab, setTab] = useState("permissions");
  function editRole(r: Role) {
    setEdit({ ...structuredClone(r), sudoers: roleSudoers(r), sudo: [] });
    setPurpose(rolePurpose(r));
    setTab(r.linux_access ? "login" : "permissions");
    setSudoPending(false);
  }
  return (
    <>
      <Stack
        direction={{ xs: "column", sm: "row" }}
        justifyContent="space-between"
        gap={2}
        mb={3}
      >
        <Tabs value={kind} onChange={(_, value) => onKindChange?.(value)}>
          <Tab value="all" label="Все роли" />
          <Tab value="application" label="Права Heimdall" />
          <Tab value="unix" label="Вход на ноды" />
        </Tabs>
        {can(me, "roles.manage") && (
          <Button
            variant="contained"
            startIcon={<Add />}
            onClick={() =>
              editRole({ ...blank, linux_access: kind === "unix" })
            }
          >
            Создать роль
          </Button>
        )}
      </Stack>
      <Typography variant="body2" color="text.secondary" mb={3}>
        Права Heimdall и UNIX-доступ задаются отдельно.{" "}
        <a href="/?page=docs&doc=access-management">
          Роли и порядок назначения
        </a>
      </Typography>
      <Stack gap={2}>
        {roles.map(normalizeRole).map((r) => (
          <Paper className="panel" key={r.id}>
            <Stack direction="row" justifyContent="space-between" gap={2}>
              <Stack direction="row" gap={2} alignItems="center">
                <SecurityOutlined color="primary" />
                <Typography variant="h6">{r.name}</Typography>
              </Stack>
              {can(me, "roles.manage") && (
                <Stack direction="row">
                  <Button onClick={() => editRole(r)}>Настроить</Button>
                  <Button color="error" onClick={() => setRemove(r)}>
                    Удалить
                  </Button>
                </Stack>
              )}
            </Stack>
            <Stack direction="row" flexWrap="wrap" gap={1} mt={2}>
              {r.permissions.length > 0 && (
                <Chip
                  size="small"
                  label={
                    r.permissions.includes("*")
                      ? "Администратор Heimdall"
                      : `Права Heimdall: ${r.permissions.length}`
                  }
                />
              )}
              {r.linux_access && (
                <>
                  <Chip size="small" label="UNIX-доступ" />
                  {r.allow_ssh_keys && (
                    <Chip size="small" variant="outlined" label="SSH-ключи" />
                  )}
                  {r.allow_password && (
                    <Chip size="small" variant="outlined" label="UNIX-пароль" />
                  )}
                  {!r.allow_password && !r.allow_ssh_keys && (
                    <Chip
                      size="small"
                      color="warning"
                      label="Способы входа запрещены"
                    />
                  )}
                </>
              )}
              {!r.permissions.length && !r.linux_access && (
                <Typography color="text.secondary">
                  Разрешения не заданы
                </Typography>
              )}
            </Stack>
            {r.permissions.length > 0 && (
              <Typography variant="body2" color="text.secondary" mt={2}>
                {r.permissions.map(permissionName).join(" · ")}
              </Typography>
            )}
            {(r.sudoers || r.sudo.length > 0) && (
              <Typography
                component="pre"
                className="mono"
                sx={{ whiteSpace: "pre-wrap", fontSize: 13 }}
              >
                {roleSudoers(r)}
              </Typography>
            )}
          </Paper>
        ))}
      </Stack>
      <Dialog open={!!remove} onClose={() => setRemove(null)}>
        <DialogTitle>Удалить роль «{remove?.name}»?</DialogTitle>
        <DialogContent>
          <Typography>
            Все назначения этой роли будут отозваны. Изменения прав на нодах
            считаются применёнными после подтверждения агентов.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRemove(null)}>Отмена</Button>
          <Button
            color="error"
            onClick={() =>
              void act(async () => {
                await api("/roles/" + remove?.id, "DELETE", undefined, {
                  confirmed: true,
                });
                setRemove(null);
              })
            }
          >
            Удалить и отозвать назначения
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog
        open={!!edit}
        onClose={() => setEdit(null)}
        fullWidth
        maxWidth="md"
      >
        <DialogTitle>{edit?.id ? "Настроить роль" : "Новая роль"}</DialogTitle>
        <DialogContent>
          {edit && (
            <Stack gap={3} pt={1}>
              <TextField
                label="Название"
                value={edit.name}
                onChange={(e) => setEdit({ ...edit, name: e.target.value })}
              />
              <TextField
                select
                label="Назначение роли"
                value={purpose}
                onChange={(e) => {
                  const next = e.target.value as RolePurpose;
                  setPurpose(next);
                  setEdit(roleWithPurpose(edit, next));
                  setTab(next === "application" ? "permissions" : "login");
                  setSudoPending(false);
                }}
                helperText="Тип определяет содержимое роли. Область действия выбирается при назначении."
              >
                <MenuItem value="application">Управление Heimdall</MenuItem>
                <MenuItem value="unix">Вход на ноды и sudo</MenuItem>
                <MenuItem value="combined">Совмещённая роль</MenuItem>
              </TextField>
              {purpose === "combined" && (
                <Alert severity="info">
                  Роль содержит права Heimdall и доступ на ОС. Через UNIX-группу
                  выдаётся только доступ на ОС; через группу людей или персональное
                  назначение — обе части. Для обычной настройки удобнее отдельные роли.
                </Alert>
              )}
              <Tabs value={tab} onChange={(_, value) => setTab(value)}>
                {purpose !== "unix" && <Tab value="permissions" label="Права Heimdall" />}
                {purpose !== "application" && <Tab value="login" label="Способы входа" />}
                {purpose !== "application" && <Tab value="sudo" label="sudoers" />}
              </Tabs>
              {tab === "permissions" && (
                <Stack gap={1}>
                  <Typography variant="body2" color="text.secondary">
                    Разрешения на управление продуктом. Они не предоставляют
                    SSH-доступ.
                  </Typography>
                  {can(me, "*") && (
                    <FormControlLabel
                      label="Все права администратора"
                      control={
                        <Checkbox
                          checked={edit.permissions.includes("*")}
                          onChange={(_, checked) =>
                            setEdit({
                              ...edit,
                              permissions: checked ? ["*"] : [],
                            })
                          }
                        />
                      }
                    />
                  )}
                  {Object.entries(resources).map(([resource, label]) => {
                    const permissions = me.permissions.filter(
                      (p) => p.startsWith(resource + ".") && can(me, p),
                    );
                    if (!permissions.length) return null;
                    return (
                      <Accordion
                        key={resource}
                        disableGutters
                        elevation={0}
                        sx={{
                          border: "1px solid #e5e9f0",
                          borderRadius: "12px !important",
                          "&:before": { display: "none" },
                        }}
                      >
                        <AccordionSummary expandIcon={<ExpandMore />}>
                          <Stack direction="row" gap={2} alignItems="center">
                            <Typography>{label}</Typography>
                            <Chip
                              size="small"
                              label={`${edit.permissions.includes("*") ? permissions.length : permissions.filter((p) => edit.permissions.includes(p)).length} / ${permissions.length}`}
                            />
                          </Stack>
                        </AccordionSummary>
                        <AccordionDetails>
                          <Stack direction="row" gap={2} flexWrap="wrap">
                            {permissions.map((p) => (
                              <FormControlLabel
                                key={p}
                                label={actions[p.split(".")[1]] || p}
                                control={
                                  <Checkbox
                                    slotProps={{
                                      input: {
                                        "aria-label": permissionName(p),
                                      },
                                    }}
                                    disabled={edit.permissions.includes("*")}
                                    checked={
                                      edit.permissions.includes("*") ||
                                      edit.permissions.includes(p)
                                    }
                                    onChange={(_, checked) =>
                                      setEdit({
                                        ...edit,
                                        permissions: checked
                                          ? [...edit.permissions, p]
                                          : edit.permissions.filter(
                                              (v) => v !== p,
                                            ),
                                      })
                                    }
                                  />
                                }
                              />
                            ))}
                          </Stack>
                        </AccordionDetails>
                      </Accordion>
                    );
                  })}
                </Stack>
              )}
              {tab === "login" && (
                <Stack gap={2}>
                  <Typography variant="body2" color="text.secondary">
                    Разрешите необходимые способы входа. Пароль Heimdall
                    не используется для входа на ОС.
                  </Typography>
                  <FormControlLabel
                    label="Разрешить вход по SSH-ключам"
                    control={
                      <Checkbox
                        disabled={!edit.linux_access}
                        checked={!!edit.allow_ssh_keys}
                        onChange={(_, checked) =>
                          setEdit({ ...edit, allow_ssh_keys: checked })
                        }
                      />
                    }
                  />
                  <FormControlLabel
                    label="Разрешить вход по UNIX-паролю"
                    control={
                      <Checkbox
                        disabled={!edit.linux_access}
                        checked={!!edit.allow_password}
                        onChange={(_, checked) =>
                          setEdit({ ...edit, allow_password: checked })
                        }
                      />
                    }
                  />
                  {edit.linux_access &&
                    !edit.allow_password &&
                    !edit.allow_ssh_keys && (
                      <Alert severity="warning">
                        Эта роль не разрешает ни один способ входа. Доступ
                        возможен только если другой назначенной ролью явно
                        разрешён метод.
                      </Alert>
                    )}
                  <Typography variant="body2" color="text.secondary">
                    У пользователя также должна быть включена синхронизация
                    UNIX-учётки. Назначьте роль через UNIX-группу и группу нод.
                  </Typography>
                </Stack>
              )}
              {tab === "sudo" && (
                <SudoEditor
                  value={edit.sudoers || ""}
                  onPendingChange={setSudoPending}
                  disabled={!can(me, "sudo.manage")}
                  onChange={(text) =>
                    setEdit({ ...edit, sudoers: text, sudo: [] })
                  }
                />
              )}
            </Stack>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEdit(null)}>Отмена</Button>
          <Button
            variant="contained"
            disabled={!edit?.name.trim() || (edit?.linux_access && sudoPending)}
            onClick={() =>
              void act(async () => {
                await api("/roles", "POST", edit);
                setEdit(null);
              })
            }
          >
            Сохранить
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
}
export function roleSudoers(r: Role): string {
  return [
    r.sudoers || "",
    ...(r.sudo || []).map(
      (s) =>
        `ALL=(${s.run_as}) ${s.no_password ? "NOPASSWD" : "PASSWD"}: ${s.command} ${s.arguments?.length ? s.arguments.join(" ") : '""'}`,
    ),
  ]
    .filter(Boolean)
    .join("\n");
}
