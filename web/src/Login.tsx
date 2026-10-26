import { useEffect, useState } from "react";
import {
  Alert,
  Box,
  Button,
  Paper,
  Stack,
  MenuItem,
  TextField,
  Typography,
} from "@mui/material";
import { Logo } from "./Logo";
import { Fingerprint } from "@mui/icons-material";
import { startAuthentication } from "@simplewebauthn/browser";
import { api } from "./api";
export function Login({ onLogin }: { onLogin: () => void }) {
  const [login, setLogin] = useState("admin"),
    [password, setPassword] = useState(""),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false),
    [challenge, setChallenge] = useState(""),
    [code, setCode] = useState(""),
    [recoveryOnly, setRecoveryOnly] = useState(false),
    [provider, setProvider] = useState("");
  const invitationPage = location.pathname === "/invite";
  const invite = invitationPage ? location.hash.slice(1) : "";
  const [providers, setProviders] = useState<{ id: string; type: string }[]>(
    [],
  );
  useEffect(() => {
    api<{ id: string; type: string }[]>("/auth/providers")
      .then(setProviders)
      .catch((e: Error) =>
        setError("Провайдеры входа недоступны: " + e.message),
      );
    if (location.hash.startsWith("#totp="))
      setChallenge(location.hash.slice(6));
    if (location.hash.startsWith("#passkey=")) setLogin(location.hash.slice(9));
  }, []);
  async function run(fn: () => Promise<void>) {
    setBusy(true);
    setError("");
    try {
      await fn();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function passkey() {
    const options = await api<{
      publicKey: Parameters<typeof startAuthentication>[0]["optionsJSON"];
    }>("/auth/passkey/begin", "POST", { login });
    const credential = await startAuthentication({
      optionsJSON: options.publicKey,
    });
    await api("/auth/passkey/finish", "POST", credential);
    history.replaceState({}, "", "/");
    onLogin();
  }
  async function submit() {
    if (challenge) {
      await api("/auth/totp", "POST", { challenge, code });
      history.replaceState({}, "", "/");
      onLogin();
      return;
    }
    if (invitationPage) {
      if (!invite) throw new Error("В ссылке приглашения отсутствует токен");
      await api("/auth/invitation", "POST", { token: invite, password });
      history.replaceState({}, "", "/");
      onLogin();
      return;
    }
    const result = await api<{
      totp_required?: boolean;
      challenge?: string;
      passkey_required?: boolean;
    }>("/auth/login", "POST", { login, password, provider });
    if (result.totp_required) {
      setChallenge(result.challenge || "");
      return;
    }
    if (result.passkey_required) {
      setRecoveryOnly(true);
      setChallenge(result.challenge || "");
      await passkey();
      return;
    }
    onLogin();
  }
  return (
    <Box className="login-shell">
      <Paper className="login-form">
        <Stack direction="row" gap={1} alignItems="center" mb={3}>
          <Logo size={40} />
          <Typography variant="h5">Heimdall</Typography>
        </Stack>
        <Typography variant="h5" mb={1}>
          {invitationPage
            ? "Первый вход"
            : challenge
              ? "Подтвердите вход"
              : "Вход"}
        </Typography>
        <Typography color="text.secondary" mb={4}>
          {invitationPage
            ? "Задайте пароль от Heimdall. Пароль для входа на UNIX настраивается отдельно."
            : challenge
              ? recoveryOnly
                ? "Используйте passkey или одноразовый резервный код."
                : "Введите код TOTP или одноразовый резервный код."
              : ""}
        </Typography>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void run(submit);
          }}
        >
          <Stack gap={2.5}>
            {error && <Alert severity="error">{error}</Alert>}
            {!invitationPage &&
              !challenge &&
              providers.some((p) => p.type === "ldap") && (
                <TextField
                  select
                  label="Провайдер"
                  value={provider}
                  onChange={(e) => setProvider(e.target.value)}
                >
                  <MenuItem value="">Локальный Heimdall</MenuItem>
                  {providers
                    .filter((p) => p.type === "ldap")
                    .map((p) => (
                      <MenuItem key={p.id} value={p.id}>
                        {p.id}
                      </MenuItem>
                    ))}
                </TextField>
              )}
            {!invitationPage && !challenge && (
              <TextField
                label="Логин"
                value={login}
                onChange={(e) => setLogin(e.target.value)}
                autoComplete="username"
                required
              />
            )}
            {challenge ? (
              <TextField
                label={
                  recoveryOnly ? "Резервный код" : "Код TOTP или резервный код"
                }
                value={code}
                onChange={(e) => setCode(e.target.value)}
                inputProps={{ maxLength: 60 }}
                autoFocus
                required
              />
            ) : (
              <TextField
                label={
                  invite ? "Новый пароль · не менее 12 символов" : "Пароль"
                }
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete={invite ? "new-password" : "current-password"}
                required
                inputProps={{
                  minLength: invite ? 12 : undefined,
                  maxLength: 1024,
                }}
              />
            )}
            <Button
              type="submit"
              variant="contained"
              disabled={busy}
              size="large"
            >
              {busy
                ? "Проверяем…"
                : invite
                  ? "Создать пароль"
                  : challenge
                    ? "Подтвердить"
                    : "Войти"}
            </Button>
            {!invitationPage && !challenge && (
              <>
                <Button
                  startIcon={<Fingerprint />}
                  variant="outlined"
                  disabled={busy}
                  onClick={() => void run(passkey)}
                >
                  Войти с passkey
                </Button>
                {providers
                  .filter((p) => p.type === "oidc")
                  .map((p) => (
                    <Button
                      key={p.id}
                      href={"/api/v1/auth/oidc/" + p.id + "/start"}
                    >
                      Войти через {p.id}
                    </Button>
                  ))}
              </>
            )}
          </Stack>
        </form>
      </Paper>
    </Box>
  );
}
