import { useEffect, useState } from "react";
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Alert,
  Box,
  Button,
  CircularProgress,
  Paper,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import {
  ContentCopyOutlined,
  DnsOutlined,
  ExpandMore,
} from "@mui/icons-material";
import { NodeHealth } from "./NodeHealth";
import { Pagination, useCollection } from "./Pagination";
import type { SudoRule } from "./types";
export type AccessibleNode = {
  id: string;
  name: string;
  hostname: string;
  addresses: string[];
  platform: string;
  group_name: string;
  host: string;
  port: number;
  login: string;
  access_status: string;
  health: string;
  roles: {
    name: string;
    allow_password: boolean;
    allow_ssh_keys: boolean;
    sudoers: string;
    sudo: SudoRule[];
  }[];
};
export function AvailableNodes({
  version,
  userID,
}: {
  version?: number;
  userID?: string;
}) {
  const [search, setSearch] = useState(""),
    [query, setQuery] = useState(""),
    [copied, setCopied] = useState(""),
    [copyError, setCopyError] = useState("");
  useEffect(() => {
    const timer = setTimeout(() => setQuery(search.trim()), 250);
    return () => clearTimeout(timer);
  }, [search]);
  const nodes = useCollection<AccessibleNode>(
    (userID ? `/users/${userID}/nodes` : "/me/nodes") +
      "?query=" +
      encodeURIComponent(query),
    version,
  );
  return (
    <Stack gap={2}>
      <TextField
        label="Поиск нод"
        placeholder="Имя, hostname, IP-адрес или группа"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        fullWidth
      />
      {nodes.error && <Alert severity="error">{nodes.error}</Alert>}
      {copyError && (
        <Alert severity="error" onClose={() => setCopyError("")}>
          {copyError}
        </Alert>
      )}
      {nodes.loading && (
        <CircularProgress size={24} aria-label="Загрузка нод" />
      )}
      {!nodes.loading && !nodes.error && !nodes.items.length && (
        <Paper className="panel">
          <Typography color="text.secondary">
            {query
              ? "Ноды по этому запросу не найдены."
              : "Доступ к нодам пока не назначен. Обратитесь к администратору."}
          </Typography>
        </Paper>
      )}
      <Box
        sx={{
          display: "grid",
          gridTemplateColumns:
            "repeat(auto-fit, minmax(min(100%, 360px), 1fr))",
          gap: 2,
        }}
      >
        {nodes.items.map((n) => {
          const command = `ssh${n.port !== 22 ? " -p " + n.port : ""} ${n.login}@${n.host}`;
          return (
            <Paper className="panel" key={n.id} sx={{ minWidth: 0 }}>
              <Stack gap={2}>
                <Stack
                  direction="row"
                  gap={1}
                  alignItems="center"
                  flexWrap="wrap"
                >
                  <DnsOutlined color="primary" />
                  <Typography
                    variant="h6"
                    sx={{ flex: 1, overflowWrap: "anywhere" }}
                  >
                    {n.name}
                  </Typography>
                  <NodeHealth
                    node={{
                      health: n.health,
                      disabled: false,
                      connectivity: "",
                      status: n.access_status,
                    }}
                  />
                </Stack>
                <Stack gap={0.5}>
                  <Typography>{n.group_name}</Typography>
                  <Typography variant="body2" color="text.secondary">
                    {n.hostname || n.host} · {n.platform || "UNIX"}
                  </Typography>
                  <Typography
                    variant="body2"
                    color="text.secondary"
                    sx={{ overflowWrap: "anywhere" }}
                  >
                    {(n.addresses || []).join(", ") || n.host}
                  </Typography>
                  <Typography variant="body2">
                    UNIX-пользователь: <strong>{n.login}</strong>
                  </Typography>
                  <Typography variant="body2">
                    Вход:{" "}
                    {[
                      n.roles.some((r) => r.allow_ssh_keys) && "SSH-ключ",
                      n.roles.some((r) => r.allow_password) && "UNIX-пароль",
                    ]
                      .filter(Boolean)
                      .join(", ") || "не разрешён"}
                  </Typography>
                </Stack>
                <Box
                  component="code"
                  sx={{
                    p: 1.5,
                    bgcolor: "action.hover",
                    borderRadius: 1,
                    overflowWrap: "anywhere",
                  }}
                >
                  {command}
                </Box>
                <Button
                  startIcon={<ContentCopyOutlined />}
                  sx={{ alignSelf: "flex-start" }}
                  onClick={() => {
                    void navigator.clipboard
                      .writeText(command)
                      .then(() => {
                        setCopied(n.id);
                        setCopyError("");
                      })
                      .catch(() =>
                        setCopyError(
                          "Не удалось скопировать команду. Скопируйте её вручную.",
                        ),
                      );
                  }}
                >
                  {copied === n.id ? "Скопировано" : "Копировать SSH-команду"}
                </Button>
                <Accordion
                  disableGutters
                  elevation={0}
                  sx={{
                    border: "1px solid",
                    borderColor: "divider",
                    borderRadius: 1,
                    "&:before": { display: "none" },
                  }}
                >
                  <AccordionSummary expandIcon={<ExpandMore />}>
                    <Typography variant="body2">
                      Роли и sudo · {n.roles.length}
                    </Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Stack gap={2}>
                      {n.roles.map((role) => (
                        <Box key={role.name}>
                          <Typography fontWeight={600}>{role.name}</Typography>
                          {role.sudoers && (
                            <Box
                              component="pre"
                              sx={{
                                whiteSpace: "pre-wrap",
                                overflowWrap: "anywhere",
                                fontSize: 12,
                              }}
                            >
                              {role.sudoers}
                            </Box>
                          )}
                          {(role.sudo || []).map((rule, i) => (
                            <Typography
                              component="code"
                              display="block"
                              variant="body2"
                              key={i}
                            >{`ALL=(${rule.run_as}) ${rule.no_password ? "NOPASSWD: " : ""}${rule.command} ${(rule.arguments || []).join(" ")}`}</Typography>
                          ))}
                          {!role.sudoers && !(role.sudo || []).length && (
                            <Typography variant="body2" color="text.secondary">
                              Без sudo
                            </Typography>
                          )}
                        </Box>
                      ))}
                    </Stack>
                  </AccordionDetails>
                </Accordion>
              </Stack>
            </Paper>
          );
        })}
      </Box>
      <Pagination
        index={nodes.index}
        next={!!nodes.next}
        previous={nodes.previous}
        advance={nodes.advance}
      />
    </Stack>
  );
}
