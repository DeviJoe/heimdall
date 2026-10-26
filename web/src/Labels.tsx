import { useEffect, useState } from "react";
import {
  Alert,
  Button,
  MenuItem,
  Paper,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import { api, can } from "./api";
import { ResourceSelect } from "./ResourceSelect";
import type { Group, Me } from "./types";
type Policy = {
  resource_type: string;
  resource_id: string;
  label: { level: number; categories: string[] };
};
const levels = ["Public", "Internal", "Confidential", "Secret"];
export function Labels({
  me,
  act,
}: {
  me: Me;
  groups: Group[];
  act: (fn: () => Promise<unknown>) => Promise<void>;
}) {
  const [type, setType] = useState("user"),
    [id, setID] = useState(""),
    [level, setLevel] = useState(0),
    [categories, setCategories] = useState(""),
    [error, setError] = useState(""),
    [loading, setLoading] = useState(false);
  useEffect(() => {
    setError("");
    setLevel(0);
    setCategories("");
    if (!id || !can(me, "security.manage")) return;
    let active = true;
    setLoading(true);
    void api<Policy[]>(
      `/security/labels?resource_type=${type}&resource_id=${id}`,
    )
      .then((items) => {
        if (active) {
          setLevel(items[0]?.label.level || 0);
          setCategories(items[0]?.label.categories.join(", ") || "");
        }
      })
      .catch((e) => {
        if (active) setError(e.message);
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [type, id]);
  if (!can(me, "security.manage")) return null;
  return (
    <Paper className="panel">
      <Stack gap={3}>
        <Typography variant="h6">Мандатные ограничения входа</Typography>
        {error && <Alert severity="error">{error}</Alert>}
        <Typography color="text.secondary">
          Уровень допуска и категории пользователя должны покрывать требования
          группы нод, включая унаследованные. Для входа также требуется
          назначение доступа через RBAC.
        </Typography>
        <TextField
          select
          label="Объект"
          value={type}
          onChange={(e) => {
            setType(e.target.value);
            setID("");
          }}
        >
          <MenuItem value="user">Допуск пользователя</MenuItem>
          <MenuItem value="node_group">Метки группы нод</MenuItem>
        </TextField>
        <ResourceSelect
          key={type}
          resource={type === "user" ? "/users" : "/groups"}
          label={type === "user" ? "Пользователь" : "Группа нод"}
          value={id}
          onChange={setID}
        />
        <TextField
          select
          label="Уровень"
          value={level}
          disabled={!id || loading}
          onChange={(e) => setLevel(Number(e.target.value))}
        >
          {levels.map((l, i) => (
            <MenuItem key={i} value={i}>
              {i} · {l}
            </MenuItem>
          ))}
        </TextField>
        <TextField
          label="Категории · через запятую"
          value={categories}
          disabled={!id || loading}
          onChange={(e) => setCategories(e.target.value)}
          helperText="Например: production, finance. Пустой список — без категорий."
        />
        <Button
          variant="outlined"
          disabled={!id || loading || !!error}
          onClick={() =>
            void act(async () => {
              await api("/security/labels", "POST", {
                resource_type: type,
                resource_id: id,
                label: {
                  level,
                  categories: categories
                    .split(",")
                    .map((c) => c.trim())
                    .filter(Boolean),
                },
              });
            })
          }
        >
          Сохранить и синхронизировать ограничения
        </Button>
      </Stack>
    </Paper>
  );
}
