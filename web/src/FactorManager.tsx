import { useEffect, useState } from "react";
import {
  Alert,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  MenuItem,
  Paper,
  Stack,
  TableCell,
  TableRow,
  TextField,
  Typography,
} from "@mui/material";
import { api, can, date } from "./api";
import { Pagination } from "./Pagination";
import { DataTable } from "./common";
import { describeFactorPolicies, factorPolicies } from "./factorPolicies";
import type { Me, User } from "./types";
type Passkey = {
  id: string;
  name: string;
  created_at: string | null;
  last_used: string | null;
};
type Factors = {
  passkeys: Passkey[];
  totp_enabled: boolean;
  required: string[];
  administrator_required: string[];
  personal_policy: string;
  can_remove_totp: boolean;
  can_remove_passkey: boolean;
};
export function FactorManager({
  me,
  user,
  act,
  onRotateTOTP,
}: {
  onRotateTOTP?: () => void;
  me: Me;
  user: User;
  act: (fn: () => Promise<unknown>) => Promise<void>;
}) {
  const [index, setIndex] = useState(0);
  const [factors, setFactors] = useState<Factors | null>(null),
    [names, setNames] = useState<Record<string, string>>({}),
    [remove, setRemove] = useState<string | null>(null),
    [personalPolicy, setPersonalPolicy] = useState<string | null>(null),
    [error, setError] = useState("");
  const own = me.user.id === user.id,
    manage = (own && !me.principal.restricted) || can(me, "users.manage");
  async function load() {
    const updated: Factors = await api("/users/" + user.id + "/factors");
    setIndex((i) =>
      Math.min(i, Math.max(0, Math.ceil(updated.passkeys.length / 10) - 1)),
    );
    setFactors(updated);
    setError("");
  }
  useEffect(() => {
    void load().catch((e) => setError(e.message));
  }, [user.id, user.passkey_count, user.totp_enabled]);
  return (
    <Paper className="panel">
      <Stack gap={2}>
        <Typography variant="h6">Подключённые факторы входа</Typography>
        {error && <Alert severity="error">{error}</Alert>}
        {factors && (
          <>
            <Stack direction="row" alignItems="center" gap={2}>
              <Typography sx={{ flex: 1 }}>
                TOTP · {factors.totp_enabled ? "Включён" : "Не настроен"}
              </Typography>
              {factors.totp_enabled && manage && (
                <Stack alignItems="flex-end">
                  {own && onRotateTOTP && (
                    <Button onClick={onRotateTOTP}>Заменить TOTP</Button>
                  )}
                  <Button
                    color="error"
                    disabled={!factors.can_remove_totp}
                    onClick={() => setRemove("totp")}
                  >
                    Отвязать TOTP
                  </Button>
                  {!factors.can_remove_totp && (
                    <Typography variant="caption">
                      Требуется политикой
                    </Typography>
                  )}
                </Stack>
              )}
            </Stack>
            {factors.passkeys.length ? (
              <DataTable
                heads={["Passkey", "Зарегистрирован", "Последний вход", ""]}
                empty={!factors.passkeys.length}
              >
                {factors.passkeys
                  .slice(index * 10, index * 10 + 10)
                  .map((k) => (
                    <TableRow key={k.id}>
                      <TableCell>
                        <TextField
                          label="Имя passkey"
                          size="small"
                          value={names[k.id] ?? k.name}
                          disabled={!manage}
                          onChange={(e) =>
                            setNames({ ...names, [k.id]: e.target.value })
                          }
                        />
                        <Typography
                          variant="caption"
                          component="div"
                          className="mono"
                        >
                          {k.id.slice(0, 16)}…
                        </Typography>
                      </TableCell>
                      <TableCell>{date(k.created_at)}</TableCell>
                      <TableCell>{date(k.last_used)}</TableCell>
                      <TableCell>
                        {manage && (
                          <Stack>
                            <Button
                              disabled={
                                names[k.id] === undefined ||
                                names[k.id] === k.name ||
                                !names[k.id]?.trim()
                              }
                              onClick={() =>
                                void act(async () => {
                                  await api(
                                    `/users/${user.id}/passkeys/${encodeURIComponent(k.id)}`,
                                    "PUT",
                                    { name: names[k.id] },
                                  );
                                  await load();
                                })
                              }
                            >
                              Сохранить имя
                            </Button>
                            <Button
                              color="error"
                              disabled={!factors.can_remove_passkey}
                              onClick={() => setRemove(k.id)}
                            >
                              Удалить passkey
                            </Button>
                            {!factors.can_remove_passkey && (
                              <Typography variant="caption">
                                Последний обязательный Passkey
                              </Typography>
                            )}
                          </Stack>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
              </DataTable>
            ) : (
              <Typography>Passkey · Не настроен</Typography>
            )}
            {factors.passkeys.length > 10 && (
              <Pagination
                index={index}
                next={(index + 1) * 10 < factors.passkeys.length}
                previous={() => setIndex((i) => Math.max(0, i - 1))}
                advance={() => setIndex((i) => i + 1)}
              />
            )}
            <Typography variant="body2">
              Минимум администратора и групп:{" "}
              {describeFactorPolicies(
                factors.administrator_required || factors.required,
              )}
            </Typography>
            {own ? (
              <Stack gap={2}>
                <TextField
                  select
                  label="Мои дополнительные требования"
                  value={personalPolicy ?? factors.personal_policy ?? "none"}
                  helperText="Дополняют минимум администратора. Обязательные факторы сохраняются при любом выборе."
                  onChange={(e) => setPersonalPolicy(e.target.value)}
                >
                  <MenuItem value="none">По политике администратора</MenuItem>
                  {Object.entries(factorPolicies)
                    .filter(([value]) => value !== "none")
                    .map(([value, label]) => (
                      <MenuItem key={value} value={value}>
                        {label}
                      </MenuItem>
                    ))}
                </TextField>
                <Typography variant="body2">
                  Итоговое требование:{" "}
                  {describeFactorPolicies([
                    ...(factors.administrator_required || factors.required),
                    personalPolicy ?? factors.personal_policy ?? "none",
                  ])}
                </Typography>
                {me.principal.restricted && (
                  <Typography variant="body2" color="text.secondary">
                    Для доступа зарегистрируйте недостающие обязательные
                    факторы.
                  </Typography>
                )}
                <Button
                  sx={{ alignSelf: "flex-start" }}
                  variant="outlined"
                  disabled={
                    personalPolicy === null ||
                    personalPolicy === factors.personal_policy
                  }
                  onClick={() =>
                    void act(async () => {
                      await api("/me/factor-policy", "PUT", {
                        policy: personalPolicy,
                      });
                      setPersonalPolicy(null);
                      await load();
                    })
                  }
                >
                  Сохранить мои требования
                </Button>
              </Stack>
            ) : (
              <Typography variant="body2">
                Дополнительные требования пользователя:{" "}
                {factors.personal_policy === "none"
                  ? "нет"
                  : describeFactorPolicies([factors.personal_policy])}
                . Итог: {describeFactorPolicies(factors.required)}.
              </Typography>
            )}
          </>
        )}
      </Stack>
      <Dialog open={!!remove} onClose={() => setRemove(null)}>
        <DialogTitle>
          {remove === "totp" ? "Отвязать TOTP?" : "Удалить passkey?"}
        </DialogTitle>
        <DialogContent>
          <Typography>
            Фактор перестанет работать, прежние сессии будут завершены.
            {own
              ? " Оставшиеся факторы должны выполнять действующую политику."
              : " Если обязательный фактор сброшен администратором, пользователь сможет только зарегистрировать недостающий фактор; доступ к нодам будет отозван до завершения регистрации."}
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRemove(null)}>Отмена</Button>
          <Button
            color="error"
            onClick={() =>
              void act(async () => {
                await api(
                  `/users/${user.id}/${remove === "totp" ? "totp" : "passkeys/" + encodeURIComponent(remove || "")}`,
                  "DELETE",
                  undefined,
                  { confirmed: true },
                );
                setRemove(null);
                await load();
              })
            }
          >
            Отвязать фактор
          </Button>
        </DialogActions>
      </Dialog>
    </Paper>
  );
}
