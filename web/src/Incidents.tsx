import { useState } from "react";
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Alert,
  Box,
  Button,
  Checkbox,
  Chip,
  Stack,
  Typography,
} from "@mui/material";
import { ExpandMore } from "@mui/icons-material";
import { api, can, date } from "./api";
import type { Incident, Me, Node } from "./types";
const titles: Record<string, string> = {
  failed_authentication: "Ошибки входа по SSH",
  unmanaged_login: "Вход под неуправляемой учётной записью",
  apply_failed: "Ошибка применения изменений",
  sync_stalled: "Синхронизация не продвигается",
  revocation_pending: "Отзыв доступа не подтверждён",
  node_offline: "Нода не на связи",
  key_expiring: "SSH-ключ требует ротации",
};
export function groupIncidents(incidents: Incident[]) {
  const groups = new Map<string, Incident[]>();
  for (const i of incidents) {
    if (i.status === "resolved") continue;
    const key = JSON.stringify([i.kind, i.node_id, i.group_id]);
    const items = groups.get(key);
    if (items) items.push(i);
    else groups.set(key, [i]);
  }
  return [...groups.values()]
    .map((items) => ({
      items,
      count: items.reduce((n, i) => n + (i.occurrences || 1), 0),
      critical: items.some((i) => i.severity === "critical"),
      first: items.reduce(
        (a, i) => (a < i.created_at ? a : i.created_at),
        items[0].created_at,
      ),
      last: items.reduce(
        (a, i) =>
          a > (i.last_seen || i.created_at) ? a : i.last_seen || i.created_at,
        items[0].created_at,
      ),
    }))
    .sort(
      (a, b) =>
        Number(b.critical) - Number(a.critical) || b.last.localeCompare(a.last),
    );
}
export function Incidents({
  incidents,
  nodes,
  me,
  act,
}: {
  incidents: Incident[];
  nodes: Node[];
  me: Me;
  act: (fn: () => Promise<unknown>) => Promise<void>;
}) {
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const grouped = groupIncidents(incidents),
    names = new Map(nodes.map((n) => [n.id, n.name]));
  const closable = (i: Incident) =>
    ["unmanaged_login", "failed_authentication"].includes(i.kind) &&
    can(me, "incidents.manage", i.group_id || "*");
  const selectedIDs = incidents
    .filter((i) => selected.has(i.id) && i.status !== "resolved" && closable(i))
    .map((i) => i.id);
  async function close(ids: string[]) {
    await api("/incidents/resolve", "POST", { ids });
    setSelected((old) => {
      const next = new Set(old);
      ids.forEach((id) => next.delete(id));
      return next;
    });
  }
  if (!grouped.length)
    return (
      <Alert severity="success">Активных инцидентов на этой странице нет</Alert>
    );
  return (
    <Stack gap={1}>
      {selectedIDs.length > 0 && (
        <Stack direction="row" alignItems="center" gap={2}>
          <Typography>Выбрано: {selectedIDs.length}</Typography>
          <Button
            color="error"
            onClick={() => void act(() => close(selectedIDs))}
          >
            Закрыть выбранные
          </Button>
          <Button onClick={() => setSelected(new Set())}>Снять выбор</Button>
        </Stack>
      )}
      {grouped.map((group) => {
        const first = group.items[0],
          closeIDs = group.items.filter(closable).map((i) => i.id);
        return (
          <Accordion
            key={first.id}
            disableGutters
            sx={{
              borderRadius: "12px !important",
              border: "1px solid",
              borderColor: group.critical ? "error.light" : "divider",
              boxShadow: "none",
              "&:before": { display: "none" },
            }}
          >
            <AccordionSummary expandIcon={<ExpandMore />}>
              <Box minWidth={0}>
                <Stack
                  direction="row"
                  gap={1}
                  alignItems="center"
                  flexWrap="wrap"
                >
                  <Typography fontWeight={600}>
                    {titles[first.kind] || first.kind}
                  </Typography>
                  <Chip
                    size="small"
                    label={`${group.items.length} инцидентов · ${group.count} событий`}
                    color={group.critical ? "error" : "warning"}
                  />
                  {first.node_id && (
                    <Typography variant="body2">
                      {first.node_name ||
                        names.get(first.node_id) ||
                        "Нода недоступна"}
                    </Typography>
                  )}
                </Stack>
                <Typography
                  variant="body2"
                  color="text.secondary"
                  sx={{ overflowWrap: "anywhere" }}
                >
                  {first.message}
                </Typography>
                <Typography variant="caption">
                  Последнее: {date(group.last)}
                </Typography>
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <Stack gap={1}>
                {closeIDs.length > 0 && (
                  <Stack direction="row" gap={1} flexWrap="wrap">
                    <Button
                      onClick={() =>
                        setSelected((old) => new Set([...old, ...closeIDs]))
                      }
                    >
                      Выбрать группу
                    </Button>
                    <Button
                      color="error"
                      onClick={() => void act(() => close(closeIDs))}
                    >
                      Закрыть на странице ({closeIDs.length})
                    </Button>
                  </Stack>
                )}
                {group.items.map((i) => (
                  <Box key={i.id}>
                    <Stack direction="row" alignItems="flex-start">
                      {closable(i) && (
                        <Checkbox
                          slotProps={{ input: { "aria-label": `Выбрать инцидент ${i.id}` } }}
                          checked={selected.has(i.id)}
                          onChange={(_, value) =>
                            setSelected((old) => {
                              const next = new Set(old);
                              if (value) next.add(i.id);
                              else next.delete(i.id);
                              return next;
                            })
                          }
                        />
                      )}
                      <Accordion
                        disableGutters
                        sx={{
                          flex: 1,
                          boxShadow: "none",
                          border: "1px solid",
                          borderColor: "divider",
                          "&:before": { display: "none" },
                        }}
                      >
                        <AccordionSummary expandIcon={<ExpandMore />}>
                          <Box minWidth={0}>
                            <Typography variant="body2">{i.message}</Typography>
                            <Typography
                              variant="caption"
                              color="text.secondary"
                            >
                              {date(i.created_at)} · {i.occurrences || 1}{" "}
                              событий ·{" "}
                              {i.status === "acknowledged"
                                ? "Принят к работе"
                                : "Открыт"}
                            </Typography>
                          </Box>
                        </AccordionSummary>
                        <AccordionDetails>
                          <Stack gap={1}>
                            <Typography
                              sx={{
                                whiteSpace: "pre-wrap",
                                overflowWrap: "anywhere",
                              }}
                            >
                              {i.message}
                            </Typography>
                            <Typography variant="caption" className="mono">
                              ID: {i.id}
                            </Typography>
                            <Typography variant="body2">
                              Первое: {date(i.created_at)} · Последнее:{" "}
                              {date(i.last_seen || i.created_at)}
                            </Typography>
                            {closable(i) ? (
                              <Button
                                color="error"
                                onClick={() => void act(() => close([i.id]))}
                              >
                                Закрыть этот инцидент
                              </Button>
                            ) : (
                              can(me, "sync.retry", i.group_id || "*") && (
                                <>
                                  <Typography variant="caption">
                                    Закрытие после подтверждённого
                                    восстановления синхронизации.
                                  </Typography>
                                  <Button
                                    onClick={() =>
                                      void act(() =>
                                        api(
                                          `/incidents/${i.id}/acknowledge`,
                                          "POST",
                                          {},
                                        ),
                                      )
                                    }
                                  >
                                    Принять к работе
                                  </Button>
                                </>
                              )
                            )}
                          </Stack>
                        </AccordionDetails>
                      </Accordion>
                    </Stack>
                  </Box>
                ))}
              </Stack>
            </AccordionDetails>
          </Accordion>
        );
      })}
    </Stack>
  );
}
