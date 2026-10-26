import { useEffect, useState } from "react";
import {
  Alert,
  Checkbox,
  FormControlLabel,
  Button,
  Chip,
  MenuItem,
  Paper,
  Stack,
  TableCell,
  TableRow,
  TextField,
  Typography,
} from "@mui/material";
import {
  Add,
  Fingerprint,
  KeyOutlined,
  LockOutlined,
  NotificationsNone,
  Terminal,
} from "@mui/icons-material";
import { startRegistration } from "@simplewebauthn/browser";
import { QRCodeSVG } from "qrcode.react";
import { ResourceSelect } from "./ResourceSelect";
import { Pagination, useCollection } from "./Pagination";
import { factorPolicies } from "./factorPolicies";
import { AvailableNodes } from "./AvailableNodes";
import { FactorManager } from "./FactorManager";
import { api, canAny, page as apiPage, can, date } from "./api";
import { DataTable, Status } from "./common";
import { download, generateSSH } from "./ssh";
import type {
  Binding,
  Group,
  Me,
  Notification,
  Role,
  SSHKey,
  SyncTarget,
  User,
} from "./types";
type Props = {
  me: Me;
  user: User;
  groups: Group[];
  roles: Role[];
  act: (fn: () => Promise<unknown>) => Promise<void>;
};
export function Account({ me, user, groups, act }: Props) {
  const [listVersion, setListVersion] = useState(0),
    [keySearch, setKeySearch] = useState("");
  const keyList = useCollection<SSHKey>(
    `/users/${user.id}/keys?query=${encodeURIComponent(keySearch)}`,
    listVersion,
    !me.principal.restricted,
  );
  const roleList = useCollection<Binding>(
    `/users/${user.id}/bindings`,
    listVersion,
    !me.principal.restricted,
  );
  const unixList = useCollection<{
    id: string;
    name: string;
    gid: number;
    primary: boolean;
    supplementary: boolean;
  }>(`/users/${user.id}/unix-groups`, listVersion, !me.principal.restricted);
  const keys = keyList.items,
    bindings = roleList.items;
  const [sync, setSync] = useState<SyncTarget[]>([]),
    [notifications, setNotifications] = useState<Notification[]>([]),
    [name, setName] = useState("Мой ключ"),
    [publicKey, setPublicKey] = useState(""),
    [totp, setTotp] = useState<{ secret: string; uri: string } | null>(null),
    [rotatingTOTP, setRotatingTOTP] = useState(false),
    [nativePolicy, setNativePolicy] = useState<{
      sync_to_nodes: boolean;
      allow_password: boolean;
      allow_ssh_keys: boolean;
    } | null>(null),
    [code, setCode] = useState(""),
    [password, setPassword] = useState(""),
    [roleID, setRoleID] = useState(""),
    [groupID, setGroupID] = useState("*"),
    [profile, setProfile] = useState(user);
  const [recovery, setRecovery] = useState<string[]>([]),
    [localError, setLocalError] = useState(""),
    [syncCursors, setSyncCursors] = useState([""]),
    [syncIndex, setSyncIndex] = useState(0),
    [nextSync, setNextSync] = useState("");
  const own = me.user.id === user.id;
  const manage = can(me, "users.manage");
  const canMigrate = manage && user.status === "disabled";
  async function load() {
    if (me.principal.restricted) return;
    setNativePolicy(await api("/users/" + user.id + "/native-policy"));
    if (canAny(me, "sync.read")) {
      const n = await apiPage<SyncTarget>(
        "/users/" + user.id + "/sync?after=" + syncCursors[syncIndex],
      );
      setListVersion((v) => v + 1);
      setSync(n.items);
      setNextSync(n.next);
    } else {
      setSync([]);
      setNextSync("");
    }
    setLocalError("");
    if (own) setNotifications(await api<Notification[]>("/notifications"));
  }
  useEffect(() => {
    setProfile(user);
    void load().catch((e) => setLocalError(e.message));
  }, [
    user.id,
    user.status,
    me.principal.restricted,
    user.sync_to_nodes,
    syncIndex,
    syncCursors,
  ]);
  const change = (fn: () => Promise<unknown>) =>
    act(async () => {
      const result = await fn();
      await load();
      return result;
    });
  async function startTOTP(rotation = false) {
    const next = await api<{ secret: string; uri: string }>(
      rotation ? "/me/totp/rotate/begin" : "/me/totp/begin",
      "POST",
      {},
    );
    setRotatingTOTP(rotation);
    setCode("");
    setTotp(next);
  }
  async function enrollPasskey() {
    const options = await api<{
      publicKey: Parameters<typeof startRegistration>[0]["optionsJSON"];
    }>("/me/passkey/begin", "POST", {});
    const credential = await startRegistration({
      optionsJSON: options.publicKey,
    });
    const result = await api<{ recovery_codes: string[] }>(
      "/me/passkey/finish",
      "POST",
      credential,
    );
    setRecovery(result.recovery_codes);
  }
  return (
    <Stack gap={3}>
      {localError && (
        <Alert severity="error">
          Статус пользователя не обновлён: {localError}. Данные могут быть
          устаревшими.
        </Alert>
      )}
      {recovery.length > 0 && (
        <Paper className="panel">
          <Typography variant="h6">Резервные коды входа</Typography>
          <Alert severity="warning" sx={{ my: 2 }}>
            Сохраните эти одноразовые коды в защищённом месте. Они показываются
            один раз. Предыдущие коды заменены.
          </Alert>
          <Typography
            component="pre"
            className="mono"
            sx={{ overflowX: "auto" }}
          >
            {recovery.join("\n")}
          </Typography>
          <Button
            onClick={() =>
              download("heimdall-recovery-codes.txt", recovery.join("\n"))
            }
          >
            Скачать
          </Button>
          <Button onClick={() => setRecovery([])}>Коды сохранены</Button>
        </Paper>
      )}
      <Paper className="panel profile-form">
        <Stack
          direction="row"
          justifyContent="space-between"
          alignItems="center"
          mb={2}
        >
          <Stack direction="row" gap={1} alignItems="center">
            <Terminal color="primary" />
            <Typography variant="h6">Профиль · {user.login}</Typography>
          </Stack>
          <Status value={user.status} />
        </Stack>
        <FormControlLabel
          control={
            <Checkbox
              checked={!!profile.sync_to_nodes}
              disabled={!manage}
              onChange={(_, checked) =>
                setProfile({ ...profile, sync_to_nodes: checked })
              }
            />
          }
          label="Синхронизировать UNIX-учётку на ноды"
        />
        <Typography variant="body2" color="text.secondary" mb={2}>
          {profile.sync_to_nodes
            ? "Доступ требует назначения UNIX-роли с разрешённым способом входа."
            : "Учётная запись используется только в Heimdall. UNIX-доступ не предоставляется."}{" "}
          <a href="/?page=docs&doc=roles-and-groups">Правила доступа</a>
        </Typography>
        <Stack direction={{ xs: "column", sm: "row" }} gap={2}>
          <TextField
            label="Отображаемое имя"
            value={profile.display_name}
            disabled={!manage}
            onChange={(e) =>
              setProfile({ ...profile, display_name: e.target.value })
            }
          />
          <TextField
            label="Shell"
            select
            value={profile.shell}
            disabled={!manage}
            onChange={(e) => setProfile({ ...profile, shell: e.target.value })}
          >
            {[
              "/bin/bash",
              "/usr/local/bin/bash",
              "/bin/sh",
              "/usr/sbin/nologin",
            ].map((s) => (
              <MenuItem key={s} value={s}>
                {s}
              </MenuItem>
            ))}
          </TextField>
        </Stack>
        <Stack direction={{ xs: "column", sm: "row" }} gap={2} mt={2}>
          <TextField
            label="UID"
            type="number"
            value={profile.uid}
            disabled={!canMigrate}
            onChange={(e) =>
              setProfile({ ...profile, uid: Number(e.target.value) })
            }
          />
          <TextField
            label="GID · primary group"
            type="number"
            value={profile.gid}
            disabled={!canMigrate}
            onChange={(e) =>
              setProfile({ ...profile, gid: Number(e.target.value) })
            }
          />
          <TextField
            label="Домашний каталог"
            value={profile.home}
            disabled={!canMigrate}
            onChange={(e) => setProfile({ ...profile, home: e.target.value })}
          />
        </Stack>
        {canMigrate && (
          <Alert severity="warning" sx={{ mt: 2 }}>
            UID, GID и домашний каталог меняются после подтверждения блокировки
            на всех нодах. Завершите процессы пользователя перед сохранением.
          </Alert>
        )}
        <TextField
          label="GECOS"
          value={profile.gecos}
          disabled={!manage}
          onChange={(e) => setProfile({ ...profile, gecos: e.target.value })}
          sx={{ mt: 2 }}
        />
        {manage && (
          <>
            <FormControlLabel
              sx={{ mt: 2 }}
              control={
                <Checkbox
                  checked={!!profile.require_sk}
                  onChange={(_, checked) =>
                    setProfile({ ...profile, require_sk: checked })
                  }
                />
              }
              label="Разрешать только аппаратные SSH sk-ключи"
            />
            {user.kind !== "service" && (
              <TextField
                select
                label="Политика регистрации факторов"
                value={
                  profile.mfa_policy || (profile.require_mfa ? "any" : "none")
                }
                onChange={(e) =>
                  setProfile({
                    ...profile,
                    mfa_policy: e.target.value,
                    require_mfa: e.target.value !== "none",
                  })
                }
              >
                {Object.entries(factorPolicies).map(([key, label]) => (
                  <MenuItem key={key} value={key}>
                    {label}
                  </MenuItem>
                ))}
              </TextField>
            )}
            <Stack direction="row" gap={1} flexWrap="wrap">
              <Button
                variant="outlined"
                onClick={() =>
                  void change(() =>
                    api("/users/" + user.id, "PUT", {
                      ...profile,
                      maintenance: canMigrate,
                    }),
                  )
                }
              >
                Сохранить профиль
              </Button>
              {!own && (
                <>
                  <Button
                    color={user.status === "disabled" ? "primary" : "error"}
                    onClick={() =>
                      void change(() =>
                        api("/users/" + user.id + "/status", "POST", {
                          status:
                            user.status === "disabled" ? "active" : "disabled",
                        }),
                      )
                    }
                  >
                    {user.status === "disabled"
                      ? "Разблокировать"
                      : "Заблокировать"}
                  </Button>
                  <Button
                    color="error"
                    onClick={() =>
                      void change(() =>
                        api("/users/" + user.id + "/status", "POST", {
                          status: "deleted",
                        }),
                      )
                    }
                  >
                    Удалить
                  </Button>
                </>
              )}
            </Stack>
          </>
        )}
      </Paper>
      {!me.principal.restricted &&
        (own || manage) &&
        user.kind !== "service" && (
          <Paper className="panel">
            <Typography variant="h6" mb={2}>
              Доступ к нодам
            </Typography>
            <AvailableNodes userID={user.id} version={listVersion} />
          </Paper>
        )}
      {user.kind !== "service" && (
        <FactorManager
          me={me}
          user={user}
          act={act}
          onRotateTOTP={own ? () => void act(() => startTOTP(true)) : undefined}
        />
      )}
      {own && (
        <Paper className="panel">
          <Stack direction="row" alignItems="center" gap={1} mb={2}>
            <Fingerprint color="primary" />
            <Typography variant="h6">Регистрация факторов входа</Typography>
          </Stack>
          <Stack direction="row" gap={1} flexWrap="wrap" mb={2}>
            <Chip
              size="small"
              label={user.totp_enabled ? "TOTP подключён" : "TOTP не настроен"}
              color={user.totp_enabled ? "success" : "default"}
              variant="outlined"
            />
            <Chip
              size="small"
              label={`Passkey: ${user.passkey_count || 0}`}
              color={user.passkey_count ? "success" : "default"}
              variant="outlined"
            />
          </Stack>
          <Typography variant="body2" color="text.secondary" mb={2}>
            Passkey использует WebAuthn. Для SSH нужен отдельный ключ,
            зарегистрированный ниже.
          </Typography>
          <Stack direction="row" gap={1} flexWrap="wrap">
            <Button
              variant="contained"
              startIcon={<Fingerprint />}
              onClick={() => void act(enrollPasskey)}
            >
              Добавить passkey
            </Button>
            {!user.totp_enabled && (
              <Button
                variant="outlined"
                onClick={() => void act(() => startTOTP())}
              >
                Настроить TOTP
              </Button>
            )}
          </Stack>
          {totp && (
            <Stack mt={3} gap={2}>
              <Alert severity="info" sx={{ mb: 2 }}>
                Отсканируйте QR-код приложением аутентификации или введите
                секрет вручную, затем подтвердите одноразовым кодом.
                {rotatingTOTP &&
                  " Старый TOTP действует до подтверждения нового."}
              </Alert>
              <QRCodeSVG
                value={totp.uri}
                size={256}
                level="M"
                marginSize={4}
                bgColor="#ffffff"
                fgColor="#000000"
                role="img"
                aria-label="QR-код для регистрации TOTP"
                title="Регистрация TOTP в Heimdall"
                style={{ display: "block", maxWidth: "100%", height: "auto" }}
              />
              <TextField
                label="Секрет TOTP"
                value={totp.secret}
                InputProps={{ readOnly: true }}
              />
              <Button
                onClick={() => void navigator.clipboard.writeText(totp.uri)}
                sx={{ my: 1 }}
              >
                Копировать otpauth URI
              </Button>
              <TextField
                label="Код из приложения"
                value={code}
                onChange={(e) => setCode(e.target.value)}
              />
              <Button
                variant="contained"
                sx={{ mt: 2 }}
                onClick={() =>
                  void act(async () => {
                    const result = await api<{ recovery_codes: string[] }>(
                      rotatingTOTP
                        ? "/me/totp/rotate/finish"
                        : "/me/totp/finish",
                      "POST",
                      { code },
                    );
                    setRecovery(result.recovery_codes);
                    setTotp(null);
                    setCode("");
                  })
                }
              >
                {rotatingTOTP ? "Подтвердить замену" : "Подтвердить"}
              </Button>
              <Button
                onClick={() => {
                  setTotp(null);
                  setCode("");
                }}
              >
                Отменить регистрацию
              </Button>
            </Stack>
          )}
        </Paper>
      )}
      {!me.principal.restricted && (
        <>
          <Paper className="panel">
            <Stack gap={2}>
              <Typography variant="h6">UNIX-группы</Typography>
              <Typography color="text.secondary">
                Primary GID: {profile.gid}
              </Typography>
              {unixList.error && (
                <Alert severity="error">{unixList.error}</Alert>
              )}
              {unixList.items.map((g) => (
                <Stack key={g.id} direction="row" gap={1} alignItems="center">
                  <Typography sx={{ flex: 1 }}>
                    {g.name} · GID {g.gid}
                  </Typography>
                  <Chip
                    size="small"
                    label={g.primary ? "primary" : "supplementary"}
                  />
                </Stack>
              ))}
              {!unixList.items.length && (
                <Typography color="text.secondary">
                  Нет дополнительных групп в каталоге.
                </Typography>
              )}
              <Pagination {...unixList} next={!!unixList.next} />
              {manage && (
                <Button href="/?page=unix">Настроить UNIX-группы</Button>
              )}
            </Stack>
          </Paper>
          <Paper className="panel">
            <Stack direction="row" gap={1} alignItems="center" mb={2}>
              <KeyOutlined color="primary" />
              <Typography variant="h6">SSH-ключи</Typography>
            </Stack>
            {me.require_sk && (
              <Alert severity="info" sx={{ mb: 2 }}>
                Разрешены только аппаратные sk-ключи. Создайте ключ командой
                ssh-keygen -t ed25519-sk -O verify-required и загрузите
                публичную часть.
              </Alert>
            )}
            {(keyList.error || roleList.error) && (
              <Alert severity="error">{keyList.error || roleList.error}</Alert>
            )}
            <TextField
              fullWidth
              label="Поиск SSH-ключей"
              value={keySearch}
              onChange={(e) => setKeySearch(e.target.value)}
              sx={{ mb: 2 }}
            />
            <DataTable
              heads={["Ключ", "Статус", "Срок действия", ""]}
              empty={!keys.length}
            >
              {keys.map((k) => (
                <TableRow key={k.id}>
                  <TableCell>
                    <Typography fontWeight={600}>{k.name}</Typography>
                    <Typography variant="caption" color="text.secondary">
                      {k.algorithm}
                    </Typography>
                    <Typography fontSize={11} className="mono">
                      {k.fingerprint}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Status value={k.status} />
                  </TableCell>
                  <TableCell>{date(k.expires_at)}</TableCell>
                  <TableCell>
                    {k.status === "active" && (own || manage) && (
                      <Button
                        color="error"
                        onClick={() =>
                          void change(() => api("/keys/" + k.id, "DELETE"))
                        }
                      >
                        Отозвать
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </DataTable>
            <Pagination {...keyList} next={!!keyList.next} />
            {(own || manage) && (
              <Stack gap={2} mt={3}>
                <TextField
                  label="Название ключа"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
                <TextField
                  label="Публичный SSH-ключ"
                  multiline
                  minRows={3}
                  value={publicKey}
                  onChange={(e) => setPublicKey(e.target.value)}
                  placeholder="ssh-ed25519 AAAA…"
                />
                <Stack direction="row" flexWrap="wrap" gap={1}>
                  <Button
                    variant="contained"
                    startIcon={<Add />}
                    onClick={() =>
                      void change(async () => {
                        await api("/users/" + user.id + "/keys", "POST", {
                          name,
                          public_key: publicKey,
                        });
                        setPublicKey("");
                      })
                    }
                  >
                    Добавить ключ
                  </Button>
                  {!me.require_sk && (
                    <Button
                      variant="outlined"
                      onClick={() =>
                        void act(async () => {
                          const generated = await generateSSH();
                          setPublicKey(generated.publicKey);
                          download("heimdall_ed25519", generated.privateKey);
                        })
                      }
                    >
                      Сгенерировать Ed25519 в браузере
                    </Button>
                  )}
                </Stack>
                <Typography variant="caption" color="text.secondary">
                  Срок действия: {Math.round(me.key_ttl_seconds / 86400)} дней.
                  Отозванный или истёкший ключ нельзя добавить повторно.
                  Приватный ключ создаётся в браузере и сохраняется в файл;
                  установите права chmod 600.
                </Typography>
              </Stack>
            )}
          </Paper>
          <Paper className="panel">
            <Stack direction="row" gap={1} alignItems="center" mb={2}>
              <LockOutlined color="primary" />
              <Typography variant="h6">Пароль UNIX</Typography>
            </Stack>
            <Typography color="text.secondary" variant="body2" mb={2}>
              Пустое значение отключает вход по паролю. Пароль от веб-интерфейса
              не копируется на ноды.
            </Typography>
            {nativePolicy && !nativePolicy.allow_password && (
              <Alert severity="info" sx={{ mb: 2 }}>
                Парольный вход на ноды не разрешён. Его включают в назначенной
                UNIX-роли.
              </Alert>
            )}
            {(own || manage) && nativePolicy?.allow_password && (
              <Stack direction="row" gap={2}>
                <TextField
                  label="Новый пароль UNIX"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="new-password"
                />
                <Button
                  variant="outlined"
                  sx={{ minWidth: 140 }}
                  onClick={() =>
                    void change(async () => {
                      await api(
                        "/users/" + user.id + "/linux-password",
                        "PUT",
                        { password },
                      );
                      setPassword("");
                    })
                  }
                >
                  {password ? "Установить" : "Очистить"}
                </Button>
              </Stack>
            )}
          </Paper>
          <Paper className="panel">
            <Typography variant="h6" mb={2}>
              Прямые назначения ролей
            </Typography>
            {bindings.length ? (
              bindings.map((b) => (
                <Stack
                  key={b.id}
                  direction="row"
                  justifyContent="space-between"
                  mb={1}
                >
                  <Typography>
                    {b.role.name} ·{" "}
                    {b.group_id === "*"
                      ? "Все группы"
                      : b.group_name ||
                        groups.find((g) => g.id === b.group_id)?.name ||
                        b.group_id}
                  </Typography>
                  {!own && can(me, "roles.manage", b.group_id) && (
                    <Button
                      color="error"
                      onClick={() =>
                        void change(() => api("/bindings/" + b.id, "DELETE"))
                      }
                    >
                      Снять
                    </Button>
                  )}
                </Stack>
              ))
            ) : (
              <Typography color="text.secondary">
                Прямых назначений нет. Доступ к нодам также назначается через
                группы людей и UNIX-группы.
              </Typography>
            )}
            <Pagination {...roleList} next={!!roleList.next} />
            {can(me, "roles.manage") && (
              <Stack direction={{ xs: "column", sm: "row" }} gap={2} mt={2}>
                <ResourceSelect
                  resource="/roles"
                  label="Роль"
                  value={roleID}
                  onChange={setRoleID}
                />
                <ResourceSelect
                  resource="/groups"
                  label="Группа нод"
                  value={groupID}
                  onChange={setGroupID}
                  initialLabel="Все группы"
                  extraOptions={[{ id: "*", name: "Все группы" }]}
                />
                <Button
                  variant="outlined"
                  disabled={!roleID}
                  onClick={() =>
                    void change(() =>
                      api("/bindings", "POST", {
                        user_id: user.id,
                        role_id: roleID,
                        group_id: groupID,
                      }),
                    )
                  }
                >
                  Назначить
                </Button>
              </Stack>
            )}
          </Paper>
          {canAny(me, "sync.read") && (
            <Paper className="panel">
              <Typography variant="h6" mb={2}>
                Синхронизация пользователя
              </Typography>
              <DataTable
                heads={["Нода", "Синхронизация", "Ошибка"]}
                empty={!sync.length}
              >
                {sync.map((n) => (
                  <TableRow key={n.node_id}>
                    <TableCell>{n.name}</TableCell>
                    <TableCell>
                      <Status value={n.status} />
                    </TableCell>
                    <TableCell>{n.error || "—"}</TableCell>
                  </TableRow>
                ))}
              </DataTable>
              <Stack direction="row" justifyContent="flex-end" gap={1} mt={2}>
                <Button
                  disabled={!syncIndex}
                  onClick={() => setSyncIndex(syncIndex - 1)}
                >
                  Назад
                </Button>
                <Typography sx={{ p: 1 }}>Страница {syncIndex + 1}</Typography>
                <Button
                  disabled={!nextSync}
                  onClick={() => {
                    setSyncCursors([
                      ...syncCursors.slice(0, syncIndex + 1),
                      nextSync,
                    ]);
                    setSyncIndex(syncIndex + 1);
                  }}
                >
                  Далее
                </Button>
              </Stack>
            </Paper>
          )}
          {own && (
            <Paper className="panel">
              <Stack direction="row" gap={1} alignItems="center" mb={2}>
                <NotificationsNone color="primary" />
                <Typography variant="h6">Уведомления</Typography>
              </Stack>
              <Typography color="text.secondary" mb={2}>
                Получайте инциденты синхронизации в личные сообщения. Доступ к
                содержимому проверяется перед каждой отправкой.
              </Typography>
              <Stack direction="row" gap={1}>
                {(["telegram", "mattermost"] as const).map((provider) => (
                  <Button
                    key={provider}
                    variant="outlined"
                    disabled={
                      provider === "telegram"
                        ? !me.telegram_enabled
                        : !me.mattermost_enabled
                    }
                    onClick={() =>
                      void act(async () => {
                        const r = await api<{ url: string }>(
                          "/me/notifications/" + provider + "/start",
                          "POST",
                          {},
                        );
                        location.assign(r.url);
                      })
                    }
                  >
                    Войти через{" "}
                    {provider === "telegram" ? "Telegram" : "Mattermost"}
                  </Button>
                ))}
              </Stack>
              {!me.telegram_enabled && !me.mattermost_enabled && (
                <Typography
                  variant="caption"
                  color="text.secondary"
                  display="block"
                  mt={2}
                >
                  Интеграции выключены в конфигурации. Для подключения нужны
                  реквизиты бота и OAuth-приложения.
                </Typography>
              )}
              {notifications
                .filter((n) => n.enabled)
                .map((n) => (
                  <Stack direction="row" key={n.id} alignItems="center" mt={2}>
                    <Chip label={n.provider} color="success" />
                    <Button
                      color="error"
                      onClick={() =>
                        void change(() =>
                          api("/notifications/" + n.id, "DELETE"),
                        )
                      }
                    >
                      Отключить
                    </Button>
                  </Stack>
                ))}
            </Paper>
          )}
        </>
      )}
    </Stack>
  );
}
