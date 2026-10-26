import { useEffect, useState } from "react";
import {
  Alert,
  Button,
  Checkbox,
  FormControlLabel,
  Paper,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import { api } from "./api";
import { durationSeconds, formatDuration } from "./duration";
type Settings = {
  node_certificate_ttl_seconds: number;
  certificate_policy_version: number;
  certificates_total: number;
  certificates_pending: number;
  apply_timeout_seconds: number;
  version: number;
  key_ttl_seconds: number;
  key_warn_seconds: number;
  require_sk: boolean;
  stalled_seconds: number;
  offline_seconds: number;
  revocation_alert_seconds: number;
  swagger_enabled: boolean;
  mcp_enabled: boolean;
};
const durations = [
  { key: "node_certificate_ttl_seconds", label: "Срок жизни сертификатов нод", min: 86400, max: 315360000 },
  {
    key: "apply_timeout_seconds",
    label: "Ожидание подтверждения применения агентом",
    min: 60,
    max: 86400,
  },
  {
    key: "key_ttl_seconds",
    label: "Срок жизни SSH-ключей",
    min: 60,
    max: 31536000,
  },
  {
    key: "key_warn_seconds",
    label: "Предупреждать о ротации за",
    min: 0,
    max: 31536000,
  },
  {
    key: "stalled_seconds",
    label: "Порог зависшей синхронизации",
    min: 15,
    max: 86400,
  },
  { key: "offline_seconds", label: "Порог потери ноды", min: 30, max: 86400 },
  {
    key: "revocation_alert_seconds",
    label: "Порог неподтверждённой блокировки",
    min: 5,
    max: 3600,
  },
] as const;
type DurationKey = (typeof durations)[number]["key"];
export function Settings({
  act,
  updated,
}: {
  act: (fn: () => Promise<unknown>) => Promise<void>;
  updated?: unknown;
}) {
  const [value, setValue] = useState<Settings | null>(null),
    [error, setError] = useState(""),
    [draft, setDraft] = useState<Record<DurationKey, string> | null>(null),
    [rollout, setRollout] = useState({total: 0, pending: 0});
  function display(settings: Settings) {
    setValue(settings);
    setRollout({total: settings.certificates_total, pending: settings.certificates_pending});
    setDraft(
      Object.fromEntries(
        durations.map(({ key }) => [key, formatDuration(settings[key])]),
      ) as Record<DurationKey, string>,
    );
  }
  useEffect(() => {
    void api<Settings>("/settings")
      .then(display)
      .catch((e: Error) => setError(e.message));
  }, []);
  useEffect(() => {
    if (updated === undefined) return;
    let active = true;
    void api<Settings>("/settings").then((settings) => {
      if (active) setRollout({total: settings.certificates_total, pending: settings.certificates_pending});
    }).catch((e: Error) => { if (active) setError(e.message); });
    return () => { active = false; };
  }, [updated]);
  return (
    <Paper className="panel">
      <Stack gap={2}>
        {error && <Alert severity="error">{error}</Alert>}
        {value && draft && (
          <>
            <Typography variant="h6">
              Политики доступа и синхронизации
            </Typography>
            <Alert severity={rollout.pending ? "warning" : "success"}>
              Сертификаты нод: актуальны {rollout.total - rollout.pending} из {rollout.total}.
              {rollout.pending > 0 && ` Ожидают перевыпуска: ${rollout.pending}, включая offline-ноды.`}
            </Alert>
            {durations.map((field) => {
              let problem = "";
              try {
                durationSeconds(draft[field.key], field);
              } catch (e) {
                problem = (e as Error).message;
              }
              return (
                <TextField
                  key={field.key}
                  label={field.label}
                  value={draft[field.key]}
                  onChange={(e) =>
                    setDraft({ ...draft, [field.key]: e.target.value })
                  }
                  error={!!problem}
                  helperText={
                    problem ||
                    (field.key === "node_certificate_ttl_seconds"
                      ? "По умолчанию 3650d (10 лет). Изменение срока запускает перевыпуск на всех нодах; offline-ноды обновятся после подключения."
                      : field.min === 0
                      ? "Например: 7d, 12h; 0 — выключено"
                      : `s — секунды, m — минуты, h — часы, d — дни; ${formatDuration(field.min)}–${formatDuration(field.max)}`)
                  }
                />
              );
            })}
            {(
              [
                ["require_sk", "Разрешать только аппаратные SSH sk-ключи"],
                ["swagger_enabled", "Swagger"],
                ["mcp_enabled", "MCP сервер"],
              ] as const
            ).map(([key, label]) => (
              <FormControlLabel
                key={key}
                label={label}
                control={
                  <Checkbox
                    checked={value[key]}
                    onChange={(e) =>
                      setValue({ ...value, [key]: e.target.checked })
                    }
                  />
                }
              />
            ))}
            <Button
              variant="contained"
              onClick={() =>
                void act(async () => {
                  const updated = { ...value };
                  for (const field of durations)
                    updated[field.key] = durationSeconds(
                      draft[field.key],
                      field,
                    );
                  await api("/settings", "PUT", updated);
                  display(await api<Settings>("/settings"));
                })
              }
            >
              Сохранить
            </Button>
          </>
        )}
      </Stack>
    </Paper>
  );
}
