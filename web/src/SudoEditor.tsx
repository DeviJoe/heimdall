import { useEffect, useState } from "react";
import {
  Alert,
  Box,
  Button,
  Checkbox,
  FormControlLabel,
  IconButton,
  Stack,
  Tab,
  Tabs,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import { DeleteOutline, EditOutlined } from "@mui/icons-material";
export type SudoDraft = {
  hosts: string;
  runAs: string;
  command: string;
  arguments: string;
  noPassword: boolean;
};
const empty: SudoDraft = {
  hosts: "ALL",
  runAs: "root",
  command: "",
  arguments: "",
  noPassword: true,
};
export function renderSudoRule(rule: SudoDraft) {
  return `${rule.hosts.trim()}=(${rule.runAs.trim()}) ${rule.noPassword ? "NOPASSWD" : "PASSWD"}: ${rule.command.trim()} ${rule.arguments.trim() || '""'}`;
}
export function parseSudoRule(line: string): SudoDraft | null {
  const match = line.match(
    /^([\w.,!%-]+)=\(([\w.,!%:#-]+)\) (NOPASSWD|PASSWD): (\/[\w./+-]+) (.*)$/,
  );
  if (!match || match[5].includes(",") || match[5].endsWith("\\")) return null;
  return {
    hosts: match[1],
    runAs: match[2],
    command: match[4],
    arguments: match[5] === '""' ? "" : match[5],
    noPassword: match[3] === "NOPASSWD",
  };
}
export function SudoEditor({
  value,
  onChange,
  disabled = false,
  onPendingChange,
}: {
  value: string;
  onChange: (text: string) => void;
  disabled?: boolean;
  onPendingChange?: (pending: boolean) => void;
}) {
  const [tab, setTab] = useState("text"),
    [draft, setDraft] = useState<SudoDraft>({ ...empty }),
    [editing, setEditing] = useState<number | null>(null);
  const lines = value.split("\n"),
    preview = renderSudoRule(draft);
  const valid =
    draft.command.startsWith("/") &&
    !!draft.hosts.trim() &&
    !!draft.runAs.trim() &&
    Object.values(draft).every(
      (v) => typeof v !== "string" || !/[\r\n\0]/.test(v),
    );
  const pending = !!draft.command.trim();
  useEffect(() => {
    onPendingChange?.(pending);
  }, [pending, onPendingChange]);
  function commitDraft() {
    const next = [...lines];
    if (editing !== null) next[editing] = preview;
    else next.push(preview);
    onChange(next.filter((line) => line.trim()).join("\n"));
    setDraft({ ...empty });
    setEditing(null);
  }
  return (
    <Stack gap={2}>
      <Tabs
        value={tab}
        onChange={(_, v) => {
          if (v === "text" && pending && valid) commitDraft();
          setTab(v);
        }}
        aria-label="Редактор sudoers"
      >
        <Tab value="builder" label="Конструктор" />
        <Tab value="text" label="Текст" />
      </Tabs>
      {pending && (
        <Alert severity="info">
          {valid
            ? "Правило будет добавлено при переходе на вкладку «Текст»; либо нажмите «Добавить в sudoers»."
            : "Завершите правило: укажите полный путь команды, Host_List и Runas."}
        </Alert>
      )}
      {tab === "text" ? (
        <TextField
          multiline
          minRows={5}
          label="User_Spec после имени UNIX-пользователя"
          value={value}
          disabled={disabled}
          onChange={(e) => onChange(e.target.value)}
          placeholder={
            "ALL=(ALL:ALL) NOPASSWD: /usr/bin/systemctl restart nginx, /usr/bin/journalctl *"
          }
          helperText="Одна строка на правило. Агент подставляет логин и проверяет файл через visudo."
        />
      ) : (
        <>
          {lines.map((line, index) => {
            if (!line.trim()) return null;
            const parsed = parseSudoRule(line);
            return (
              <Stack key={index} direction="row" gap={1} alignItems="center">
                <Typography
                  component="code"
                  className="mono"
                  sx={{ flex: 1, overflowWrap: "anywhere" }}
                >
                  {line}
                </Typography>
                {parsed && (
                  <Tooltip title="Изменить правило">
                    <span>
                      <IconButton
                        aria-label="Изменить правило"
                        disabled={disabled}
                        onClick={() => {
                          setDraft(parsed);
                          setEditing(index);
                        }}
                      >
                        <EditOutlined />
                      </IconButton>
                    </span>
                  </Tooltip>
                )}
                <Tooltip title="Удалить правило">
                  <span>
                    <IconButton
                      aria-label="Удалить правило"
                      disabled={disabled}
                      color="error"
                      onClick={() =>
                        onChange(lines.filter((_, i) => i !== index).join("\n"))
                      }
                    >
                      <DeleteOutline />
                    </IconButton>
                  </span>
                </Tooltip>
              </Stack>
            );
          })}
          {lines.some((line) => line.trim() && !parseSudoRule(line)) && (
            <Alert severity="info">
              Есть правила с расширенным синтаксисом. Их можно изменять на
              вкладке «Текст».
            </Alert>
          )}
          <Typography fontWeight={600}>
            {editing === null ? "Добавить правило" : "Изменить правило"}
          </Typography>
          <Stack direction={{ xs: "column", sm: "row" }} gap={2}>
            <TextField
              label="Хосты (Host_List)"
              value={draft.hosts}
              disabled={disabled}
              onChange={(e) => setDraft({ ...draft, hosts: e.target.value })}
            />
            <TextField
              label="Runas: пользователь[:группа]"
              value={draft.runAs}
              disabled={disabled}
              onChange={(e) => setDraft({ ...draft, runAs: e.target.value })}
            />
          </Stack>
          <TextField
            label="Команда · полный путь"
            value={draft.command}
            disabled={disabled}
            onChange={(e) => setDraft({ ...draft, command: e.target.value })}
          />
          <TextField
            label="Аргументы · пусто означает без аргументов"
            value={draft.arguments}
            disabled={disabled}
            onChange={(e) => setDraft({ ...draft, arguments: e.target.value })}
          />
          <FormControlLabel
            label="NOPASSWD · без пароля"
            control={
              <Checkbox
                checked={draft.noPassword}
                disabled={disabled}
                onChange={(_, v) => setDraft({ ...draft, noPassword: v })}
              />
            }
          />
          <Typography variant="body2">Результат правила</Typography>
          <Box
            component="pre"
            className="mono"
            sx={{
              whiteSpace: "pre-wrap",
              m: 0,
              p: 2,
              bgcolor: "action.hover",
              borderRadius: 2,
            }}
          >
            {draft.command.trim() ? preview : "Укажите команду"}
          </Box>
          <Stack direction="row" gap={1}>
            <Button disabled={disabled || !valid} onClick={commitDraft}>
              {editing === null ? "Добавить в sudoers" : "Применить правило"}
            </Button>
            {editing !== null && (
              <Button
                onClick={() => {
                  setEditing(null);
                  setDraft({ ...empty });
                }}
              >
                Отменить изменение
              </Button>
            )}
          </Stack>
          <Typography variant="body2">Итоговый sudoers</Typography>
          <Box
            component="pre"
            className="mono"
            sx={{
              whiteSpace: "pre-wrap",
              m: 0,
              p: 2,
              bgcolor: "action.hover",
              borderRadius: 2,
            }}
          >
            {value || "—"}
          </Box>
        </>
      )}
    </Stack>
  );
}
