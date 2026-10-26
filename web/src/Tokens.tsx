import { useState } from "react";
import {
  Alert,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  MenuItem,
  Paper,
  Select,
  Stack,
  TableCell,
  TableRow,
  TextField,
  Typography,
} from "@mui/material";
import { Add } from "@mui/icons-material";
import { api, can, date } from "./api";
import type { Group, Me, Token } from "./types";
import { Pagination, useCollection } from "./Pagination";
import { ResourceSelect } from "./ResourceSelect";
import { DataTable, Status } from "./common";
export function Tokens({
  me,
  groups,
  act,
}: {
  me: Me;
  groups: Group[];
  act: (fn: () => Promise<unknown>) => Promise<void>;
}) {
  const [search, setSearch] = useState("");
  const listing = useCollection<Token>(
    "/tokens?query=" + encodeURIComponent(search),
  );
  const tokens = listing.items;
  const [open, setOpen] = useState(false),
    [secret, setSecret] = useState(""),
    [name, setName] = useState("Автоматизация"),
    [audiences, setAudiences] = useState(["api", "mcp"]),
    [scopes, setScopes] = useState(["self"]),
    [scopeGroups, setScopeGroups] = useState(["*"]),
    [days, setDays] = useState(7),
    [owner, setOwner] = useState(me.user.id);
  const load = listing.reload;
  const available = [
    "self",
    ...me.permissions.filter((p) =>
      me.principal.bindings.some(
        (b) =>
          (b.role.permissions ?? []).includes(p) ||
          (b.role.permissions ?? []).includes("*"),
      ),
    ),
    ...(can(me, "*") ? ["*"] : []),
  ];
  return (
    <>
      {listing.error && <Alert severity="error">{listing.error}</Alert>}
      <Paper className="panel" sx={{ mb: 3 }}>
        <Typography variant="h6" mb={1}>
          API и Model Context Protocol
        </Typography>
        <Typography color="text.secondary" mb={2}>
          Токен наследует текущие права владельца и ограничивает их выбранными
          scopes, группами и назначением. Блокировка владельца сразу запрещает
          новые обращения к API.
        </Typography>
        <Typography variant="body2" className="mono">
          API: {location.origin}/api/v1
          <br />
          MCP: {location.origin}/mcp · Streamable HTTP · Bearer token
        </Typography>
        <Stack direction="row" gap={2} mt={2}>
          {me.swagger_enabled && can(me, "api_docs.read") && (
            <Button href="/swagger" target="_blank" variant="outlined">
              Открыть Swagger
            </Button>
          )}
          <Button
            variant="contained"
            startIcon={<Add />}
            onClick={() => setOpen(true)}
          >
            Выпустить токен
          </Button>
        </Stack>
      </Paper>
      <TextField
        fullWidth
        label="Поиск API-токенов"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        sx={{ mb: 2 }}
      />
      <DataTable
        heads={["Токен", "Назначение и права", "Срок действия", "Статус", ""]}
        empty={!tokens.length}
      >
        {tokens.map((t) => (
          <TableRow key={t.id}>
            <TableCell>
              {t.name}
              <Typography
                variant="caption"
                component="div"
                color="text.secondary"
              >
                {t.owner_login}
              </Typography>
            </TableCell>
            <TableCell>
              <Typography fontSize={13}>{t.audiences.join(", ")}</Typography>
              <Typography color="text.secondary" fontSize={12}>
                {t.scopes.join(", ")}
              </Typography>
            </TableCell>
            <TableCell>{date(t.expires_at)}</TableCell>
            <TableCell>
              <Status
                value={
                  t.revoked_at
                    ? "revoked"
                    : new Date(t.expires_at) < new Date()
                      ? "expired"
                      : "active"
                }
              />
            </TableCell>
            <TableCell>
              {!t.revoked_at && (
                <Button
                  color="error"
                  onClick={() =>
                    void act(async () => {
                      await api("/tokens/" + t.id, "DELETE");
                      await load();
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
      <Dialog open={open} onClose={() => setOpen(false)} fullWidth>
        <DialogTitle>Новый токен</DialogTitle>
        <DialogContent>
          <Stack gap={2} pt={1}>
            {can(me, "tokens.manage") && (
              <ResourceSelect
                resource="/users?kind=service"
                label="Владелец токена"
                value={owner}
                onChange={(id) => {
                  setOwner(id);
                  if (id !== me.user.id)
                    setScopes((old) => old.filter((s) => s !== "self"));
                }}
                initialLabel={me.user.login}
                extraOptions={[{ id: me.user.id, name: me.user.login }]}
              />
            )}
            <TextField
              label="Название"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
            <Typography variant="body2">Назначение</Typography>
            <Select
              multiple
              fullWidth
              value={audiences}
              onChange={(e) =>
                setAudiences(
                  typeof e.target.value === "string"
                    ? e.target.value.split(",")
                    : e.target.value,
                )
              }
            >
              <MenuItem value="api">API</MenuItem>
              {me.mcp_enabled && <MenuItem value="mcp">MCP</MenuItem>}
            </Select>
            <Typography variant="body2">Права токена</Typography>
            <Select
              multiple
              fullWidth
              value={scopes}
              onChange={(e) =>
                setScopes(
                  typeof e.target.value === "string"
                    ? e.target.value.split(",")
                    : e.target.value,
                )
              }
            >
              {available.map((p) => (
                <MenuItem key={p} value={p}>
                  {p === "self"
                    ? "self · собственный профиль"
                    : p === "*"
                      ? "* · все текущие права"
                      : p}
                </MenuItem>
              ))}
            </Select>
            <Typography variant="body2">Группы серверов</Typography>
            <Stack direction="row" gap={1} flexWrap="wrap">
              {scopeGroups.map((id) => (
                <Button
                  key={id}
                  size="small"
                  onClick={() =>
                    setScopeGroups(scopeGroups.filter((g) => g !== id))
                  }
                >
                  {id === "*"
                    ? "Все разрешённые группы"
                    : groups.find((g) => g.id === id)?.name || id}{" "}
                  ×
                </Button>
              ))}
            </Stack>
            <ResourceSelect
              resource="/groups"
              label="Добавить группу"
              value=""
              onChange={(id) => {
                if (id)
                  setScopeGroups((old) =>
                    id === "*"
                      ? ["*"]
                      : Array.from(
                          new Set([...old.filter((g) => g !== "*"), id]),
                        ),
                  );
              }}
              extraOptions={[{ id: "*", name: "Все разрешённые группы" }]}
            />
            <Button onClick={() => setScopeGroups(["*"])}>
              Все разрешённые группы
            </Button>
            <TextField
              label="Срок действия · дней, максимум 30"
              type="number"
              value={days}
              inputProps={{ min: 1, max: 30 }}
              onChange={(e) => setDays(Number(e.target.value))}
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpen(false)}>Отмена</Button>
          <Button
            variant="contained"
            onClick={() =>
              void act(async () => {
                const r = await api<{ secret: string }>("/tokens", "POST", {
                  user_id: owner,
                  name,
                  audiences,
                  scopes,
                  groups: scopeGroups,
                  expires_at: new Date(
                    Date.now() + days * 86400000,
                  ).toISOString(),
                });
                setSecret(r.secret);
                setOpen(false);
                await load();
              })
            }
          >
            Выпустить
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog open={!!secret} onClose={() => setSecret("")} fullWidth>
        <DialogTitle>Сохраните токен</DialogTitle>
        <DialogContent>
          <Alert severity="warning" sx={{ mb: 2 }}>
            Секрет показан один раз. Храните его как пароль.
          </Alert>
          <TextField multiline value={secret} InputProps={{ readOnly: true }} />
          <Button
            onClick={() => void navigator.clipboard.writeText(secret)}
            sx={{ mt: 2 }}
          >
            Копировать
          </Button>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setSecret("")}>Готово</Button>
        </DialogActions>
      </Dialog>
    </>
  );
}
