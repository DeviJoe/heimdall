import { useState } from "react";
import { useDebounced } from "./useDebounced";
import {
  Alert,
  Box,
  Button,
  Checkbox,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControlLabel,
  MenuItem,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { Pagination, useCollection } from "./Pagination";
import { api, can } from "./api";
import type { Me } from "./types";
type Announcement = {
  id: string;
  title: string;
  markdown: string;
  severity: "info" | "warning" | "error" | "success";
  enabled: boolean;
  version: number;
  starts_at?: string;
  ends_at?: string | null;
};
const blank: Announcement = {
  id: "",
  title: "",
  markdown: "",
  severity: "info",
  enabled: true,
  version: 0,
};
export function SafeMarkdown({ children }: { children: string }) {
  return (
    <Markdown
      remarkPlugins={[remarkGfm]}
      skipHtml
      disallowedElements={["img"]}
      urlTransform={(url) =>
        /^(https?:\/\/|\/(?!\/)|#)/i.test(url) ? url : ""
      }
      components={{
        table: ({ children }) => (
          <Box sx={{ overflowX: "auto", my: 2 }}>
            <Box
              component="table"
              sx={{
                width: "100%",
                borderCollapse: "collapse",
                textAlign: "left",
                "& th, & td": {
                  p: 1.5,
                  borderBottom: "1px solid #e5e9f0",
                  verticalAlign: "top",
                },
                "& th": {
                  bgcolor: "#f8fafc",
                  color: "#617187",
                  fontWeight: 600,
                },
              }}
            >
              {children}
            </Box>
          </Box>
        ),
        a: ({ node, ...props }) => (
          <a
            {...props}
            target={
              props.href?.startsWith("/") || props.href?.startsWith("#")
                ? undefined
                : "_blank"
            }
            rel="noopener noreferrer"
          />
        ),
      }}
    >
      {children}
    </Markdown>
  );
}
export function Announcements({
  me,
  updated,
  act,
}: {
  me: Me;
  updated: unknown;
  act: (fn: () => Promise<unknown>) => Promise<void>;
}) {
  const [edit, setEdit] = useState<Announcement | null>(null),
    [manage, setManage] = useState(false),
    [search, setSearch] = useState("");
  const visible = useCollection<Announcement>("/announcements", updated);
  const query = useDebounced(search);
  const history = useCollection<Announcement>(
    "/announcements?status=all&query=" + encodeURIComponent(query),
    updated,
    manage,
  );
  const error = visible.error || (manage ? history.error : "");
  const items = visible.items,
    all = history.items;
  const load = visible.reload;
  const remove = (message: Announcement) =>
    void act(async () => {
      await api(
        `/announcements/${message.id}?version=${message.version}`,
        "DELETE",
      );
      if (edit?.id === message.id) setEdit(null);
      if (all.length === 1 && history.index > 0) history.previous();
      await Promise.all([history.reload(), load()]);
    });
  return (
    <Stack gap={2} mb={3}>
      {error && <Alert severity="error">Сообщения не обновлены: {error}</Alert>}
      {items.map((a) => (
        <Alert key={a.id} severity={a.severity}>
          <Typography fontWeight={600}>{a.title}</Typography>
          <SafeMarkdown>{a.markdown}</SafeMarkdown>
        </Alert>
      ))}
      {visible.next && <Pagination {...visible} next={!!visible.next} />}
      {can(me, "announcements.manage") && (
        <Button sx={{ alignSelf: "flex-end" }} onClick={() => setManage(true)}>
          Сообщения администратора
        </Button>
      )}
      <Dialog
        open={manage}
        onClose={() => setManage(false)}
        fullWidth
        maxWidth="md"
      >
        <DialogTitle>Сообщения в обзоре</DialogTitle>
        <DialogContent>
          <Stack gap={2} pt={1}>
            {history.error && <Alert severity="error">{history.error}</Alert>}
            <TextField
              label="Поиск сообщений"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
            {all.map((a) => (
              <Stack
                key={a.id}
                direction={{ xs: "column", sm: "row" }}
                alignItems={{ xs: "stretch", sm: "center" }}
                gap={2}
              >
                <Typography sx={{ flex: 1 }}>
                  {a.title} · {a.enabled ? "Включено" : "Выключено"}
                </Typography>
                <Stack direction="row" gap={1}>
                  <Button onClick={() => setEdit(a)}>Редактировать</Button>
                  <Button
                    color="error"
                    aria-label={`Удалить сообщение «${a.title}»`}
                    onClick={() => remove(a)}
                  >
                    Удалить
                  </Button>
                </Stack>
              </Stack>
            ))}
            <Pagination {...history} next={!!history.next} />
            <Button onClick={() => setEdit({ ...blank })}>
              Новое сообщение
            </Button>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setManage(false)}>Закрыть</Button>
        </DialogActions>
      </Dialog>
      <Dialog
        open={!!edit}
        onClose={() => setEdit(null)}
        fullWidth
        maxWidth="md"
      >
        <DialogTitle>Сообщение администратора</DialogTitle>
        <DialogContent>
          {edit && (
            <Stack gap={3} pt={1}>
              <TextField
                label="Заголовок"
                value={edit.title}
                onChange={(e) => setEdit({ ...edit, title: e.target.value })}
              />
              <TextField
                select
                label="Тип сообщения"
                value={edit.severity}
                onChange={(e) =>
                  setEdit({
                    ...edit,
                    severity: e.target.value as Announcement["severity"],
                  })
                }
              >
                {Object.entries({
                  info: "Информация",
                  warning: "Предупреждение",
                  error: "Ошибка",
                  success: "Успешно",
                }).map(([k, v]) => (
                  <MenuItem key={k} value={k}>
                    {v}
                  </MenuItem>
                ))}
              </TextField>
              <TextField
                label="Markdown"
                multiline
                minRows={5}
                value={edit.markdown}
                onChange={(e) => setEdit({ ...edit, markdown: e.target.value })}
              />
              <FormControlLabel
                label="Показывать в обзоре"
                control={
                  <Checkbox
                    checked={edit.enabled}
                    onChange={(_, checked) =>
                      setEdit({ ...edit, enabled: checked })
                    }
                  />
                }
              />
              <Typography variant="h6">Предпросмотр</Typography>
              <SafeMarkdown>{edit.markdown}</SafeMarkdown>
            </Stack>
          )}
        </DialogContent>
        <DialogActions>
          {edit?.id && can(me, "announcements.manage") && (
            <Button
              color="error"
              sx={{ mr: "auto" }}
              onClick={() => remove(edit)}
            >
              Удалить сообщение
            </Button>
          )}
          <Button onClick={() => setEdit(null)}>Отмена</Button>
          <Button
            disabled={!edit?.title.trim() || !edit?.markdown.trim()}
            onClick={() =>
              void act(async () => {
                if (!edit) return;
                const {
                  id,
                  title,
                  markdown,
                  severity,
                  enabled,
                  version,
                  starts_at,
                  ends_at,
                } = edit;
                await api("/announcements", "POST", {
                  id,
                  title,
                  markdown,
                  severity,
                  enabled,
                  version,
                  starts_at,
                  ends_at,
                });
                setEdit(null);
                await history.reload();
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
