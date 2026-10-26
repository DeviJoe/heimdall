import { useDebounced } from "./useDebounced";
import { useEffect, useState } from "react";
import {
  Alert,
  Box,
  Button,
  List,
  ListItemButton,
  ListItemText,
  Paper,
  Stack,
  Tab,
  Tabs,
  TextField,
  Typography,
} from "@mui/material";
import { Add, EditOutlined } from "@mui/icons-material";
import { api, can, date } from "./api";
import { SafeMarkdown } from "./Announcements";
import { Pagination, useCollection } from "./Pagination";
import type { Me } from "./types";

type Article = {
  slug: string;
  title: string;
  markdown: string;
  version: number;
  updated_at?: string;
};
const selectedArticle = () =>
  new URLSearchParams(location.search).get("doc") || "start";
export function Documentation({
  me,
  act,
}: {
  me: Me;
  act: (fn: () => Promise<unknown>) => Promise<void>;
}) {
  const [slug, setSlug] = useState(selectedArticle),
    [search, setSearch] = useState(""),
    [version, setVersion] = useState(0),
    [article, setArticle] = useState<Article | null>(null),
    [edit, setEdit] = useState<Article | null>(null),
    [tab, setTab] = useState(0),
    [error, setError] = useState(""),
    [saving, setSaving] = useState(false);
  const query = useDebounced(search);
  const listing = useCollection<Article>(
    "/documentation?limit=20&query=" + encodeURIComponent(query),
    version,
  );
  const manage = can(me, "documentation.manage");
  useEffect(() => {
    const pop = () => setSlug(selectedArticle());
    window.addEventListener("popstate", pop);
    return () => window.removeEventListener("popstate", pop);
  }, []);
  useEffect(() => {
    let active = true;
    setArticle(null);
    setError("");
    void api<Article>("/documentation/" + encodeURIComponent(slug))
      .then((value) => {
        if (active) setArticle(value);
      })
      .catch((e) => {
        if (active) setError(e.message);
      });
    return () => {
      active = false;
    };
  }, [slug, version]);
  useEffect(() => {
    if (!edit) return;
    const prevent = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = "";
    };
    window.addEventListener("beforeunload", prevent);
    return () => window.removeEventListener("beforeunload", prevent);
  }, [!!edit]);
  function open(next: string) {
    if (edit && !window.confirm("Отменить несохранённые изменения статьи?"))
      return;
    setEdit(null);
    history.pushState({}, "", "/?page=docs&doc=" + encodeURIComponent(next));
    setSlug(next);
  }
  return (
    <Stack
      direction={{ xs: "column", md: "row" }}
      gap={3}
      alignItems="flex-start"
    >
      <Paper
        className="panel"
        sx={{ width: { xs: "100%", md: 300 }, flexShrink: 0 }}
      >
        <Stack gap={2}>
          <TextField
            size="small"
            label="Поиск статей"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          {listing.error && <Alert severity="error">{listing.error}</Alert>}
          <List disablePadding>
            {listing.items.map((p) => (
              <ListItemButton
                key={p.slug}
                selected={p.slug === slug}
                href={"/?page=docs&doc=" + p.slug}
                onClick={(e) => {
                  if (e.ctrlKey || e.metaKey || e.shiftKey) return;
                  e.preventDefault();
                  open(p.slug);
                }}
              >
                <ListItemText primary={p.title} />
              </ListItemButton>
            ))}
          </List>
          {!listing.loading && !listing.items.length && (
            <Typography color="text.secondary">Статей не найдено</Typography>
          )}
          <Pagination {...listing} next={!!listing.next} />
          {manage && (
            <Button
              startIcon={<Add />}
              onClick={() => {
                setEdit({ slug: "", title: "", markdown: "# ", version: 0 });
                setTab(0);
              }}
            >
              Новая статья
            </Button>
          )}
        </Stack>
      </Paper>
      <Paper
        className="panel"
        sx={{ flex: 1, minWidth: 0, width: { xs: "100%", md: "auto" } }}
      >
        <Stack gap={2}>
          {error && <Alert severity="error">{error}</Alert>}
          {edit ? (
            <>
              <Stack direction={{ xs: "column", sm: "row" }} gap={2}>
                <TextField
                  fullWidth
                  label="Заголовок"
                  value={edit.title}
                  onChange={(e) => setEdit({ ...edit, title: e.target.value })}
                />
                <TextField
                  label="Адрес статьи"
                  disabled={edit.version > 0}
                  value={edit.slug}
                  onChange={(e) => setEdit({ ...edit, slug: e.target.value })}
                  helperText="Например: ssh-access"
                />
              </Stack>
              <Tabs value={tab} onChange={(_, v) => setTab(v)}>
                <Tab label="Markdown" />
                <Tab label="Просмотр" />
              </Tabs>
              {tab === 0 ? (
                <TextField
                  multiline
                  minRows={18}
                  maxRows={40}
                  fullWidth
                  label="Markdown статьи"
                  value={edit.markdown}
                  onChange={(e) =>
                    setEdit({ ...edit, markdown: e.target.value })
                  }
                  slotProps={{
                    input: { sx: { fontFamily: "monospace", fontSize: 14 } },
                  }}
                />
              ) : (
                <Box className="documentation-markdown">
                  <SafeMarkdown>{edit.markdown}</SafeMarkdown>
                </Box>
              )}
              <Stack direction="row" gap={2}>
                <Button
                  variant="contained"
                  disabled={
                    saving ||
                    !edit.title.trim() ||
                    !/^[a-z][a-z0-9-]{0,79}$/.test(edit.slug) ||
                    !edit.markdown.trim()
                  }
                  onClick={() =>
                    void act(async () => {
                      setSaving(true);
                      try {
                        await api("/documentation/" + edit.slug, "PUT", edit);
                        const next = edit.slug;
                        setEdit(null);
                        history.replaceState({}, "", "/?page=docs&doc=" + next);
                        setSlug(next);
                        setVersion((v) => v + 1);
                      } finally {
                        setSaving(false);
                      }
                    })
                  }
                >
                  Сохранить
                </Button>
                <Button
                  disabled={saving}
                  onClick={() => {
                    if (window.confirm("Отменить изменения статьи?"))
                      setEdit(null);
                  }}
                >
                  Отмена
                </Button>
              </Stack>
            </>
          ) : article ? (
            <>
              {manage && (
                <Button
                  startIcon={<EditOutlined />}
                  sx={{ alignSelf: "flex-end" }}
                  onClick={() => {
                    setEdit({ ...article });
                    setTab(0);
                  }}
                >
                  Редактировать
                </Button>
              )}
              <Box className="documentation-markdown">
                <SafeMarkdown>{article.markdown}</SafeMarkdown>
              </Box>
              <Typography variant="caption" color="text.secondary">
                Изменено: {date(article.updated_at || "")}
              </Typography>
            </>
          ) : (
            !error && (
              <Typography color="text.secondary">Загрузка статьи…</Typography>
            )
          )}
        </Stack>
      </Paper>
    </Stack>
  );
}
