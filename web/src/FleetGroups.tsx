import { ResourceSelect } from "./ResourceSelect";
import { useEffect, useMemo, useState } from "react";
import {
  Alert,
  Box,
  Button,
  Checkbox,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  IconButton,
  List,
  ListItemButton,
  Paper,
  Stack,
  TableCell,
  TableRow,
  TextField,
  Typography,
} from "@mui/material";
import { ChevronRight, ExpandMore } from "@mui/icons-material";
import type { Group, Me, Node } from "./types";
import { api, can } from "./api";
import { DataTable, Status } from "./common";
import { Pagination, useCollection } from "./Pagination";
export function FleetGroups({
  me,
  groups,
  act,
  onFilter,
}: {
  me: Me;
  groups: Group[];
  act: (fn: () => Promise<unknown>) => Promise<void>;
  onFilter?: (id: string) => void;
}) {
  const [search, setSearch] = useState(""),
    [selected, setSelected] = useState<Group | null>(null),
    [expanded, setExpanded] = useState<Set<string>>(new Set()),
    [edit, setEdit] = useState<Group | null>(null),
    [remove, setRemove] = useState(false),
    [move, setMove] = useState(false),
    [destination, setDestination] = useState(""),
    [hostIDs, setHostIDs] = useState<string[]>([]),
    [version, setVersion] = useState(0);
  const directory = useCollection<Group>(
    "/groups?query=" + encodeURIComponent(search),
    version,
  );
  const hosts = useCollection<Node>(
    "/nodes?group_id=" + encodeURIComponent(selected?.id || ""),
    version,
    move,
  );
  useEffect(() => {
    setSelected((current) =>
      current
        ? directory.items.find((g) => g.id === current.id) || current
        : null,
    );
  }, [directory.items]);
  const children = useMemo(() => {
    const map = new Map<string, Group[]>(),
      ids = new Set(directory.items.map((g) => g.id));
    for (const g of directory.items) {
      const key = ids.has(g.parent_id || "") ? g.parent_id! : "";
      if (!map.has(key)) map.set(key, []);
      map.get(key)!.push(g);
    }
    return map;
  }, [directory.items]);
  const checked = new Set(hostIDs);
  function choose(g: Group) {
    setSelected(g);
    setHostIDs([]);
    onFilter?.(g.id);
  }
  function tree(parent: string, depth = 0): React.ReactNode {
    return (children.get(parent) || []).map((g) => (
      <Box key={g.id}>
        <Stack
          direction="row"
          alignItems="center"
          sx={{ pl: Math.min(depth, 8) * 2 }}
        >
          {children.has(g.id) ? (
            <IconButton
              size="small"
              aria-label={`Развернуть ${g.name}`}
              onClick={() =>
                setExpanded((old) => {
                  const next = new Set(old);
                  if (next.has(g.id)) next.delete(g.id);
                  else next.add(g.id);
                  return next;
                })
              }
            >
              {expanded.has(g.id) ? <ExpandMore /> : <ChevronRight />}
            </IconButton>
          ) : (
            <Box width={32} />
          )}
          <ListItemButton
            selected={selected?.id === g.id}
            onClick={() => choose(g)}
            sx={{ borderRadius: 2, minWidth: 0 }}
          >
            <Typography noWrap sx={{ flex: 1 }}>
              {g.name}
            </Typography>
            <Chip
              size="small"
              label={g.active_nodes ?? g.nodes ?? 0}
              title="Ноды непосредственно в группе"
            />
          </ListItemButton>
        </Stack>
        {expanded.has(g.id) && depth < 32 && tree(g.id, depth + 1)}
      </Box>
    ));
  }
  async function changed(fn: () => Promise<unknown>) {
    await fn();
    setVersion((v) => v + 1);
  }
  return (
    <Paper className="panel" sx={{ mb: 3 }}>
      <Stack gap={2}>
        <Stack
          direction={{ xs: "column", sm: "row" }}
          alignItems="center"
          gap={2}
        >
          <Typography variant="h6" sx={{ flex: 1 }}>
            Группы нод
          </Typography>
          {selected && (
            <Button
              onClick={() => {
                setSelected(null);
                onFilter?.("");
              }}
            >
              Все ноды
            </Button>
          )}
          {can(me, "nodes.manage") && (
            <Button
              onClick={() =>
                setEdit({ id: "", name: "", parent_id: selected?.id || "" })
              }
            >
              Создать группу
            </Button>
          )}
        </Stack>
        {directory.error && <Alert severity="error">{directory.error}</Alert>}
        <Box
          sx={{
            display: "grid",
            gridTemplateColumns: {
              xs: "1fr",
              md: "minmax(250px,1fr) minmax(0,2fr)",
            },
            gap: 3,
          }}
        >
          <Box>
            <TextField
              fullWidth
              label="Поиск групп"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
            <List
              dense
              aria-label="Дерево групп нод"
              sx={{ maxHeight: 340, overflow: "auto", mt: 1 }}
            >
              {tree("")}
            </List>
            <Pagination {...directory} next={!!directory.next} />
          </Box>
          <Box>
            {selected ? (
              <Stack gap={2}>
                <Typography variant="h6">{selected.name}</Typography>
                <Typography variant="body2">
                  Прямое членство: {selected.nodes ?? 0} нод · подключение
                  разрешено: {selected.active_nodes ?? 0}
                </Typography>
                {selected.parent_id && (
                  <Typography variant="body2">
                    Родитель:{" "}
                    {groups.find((g) => g.id === selected.parent_id)?.name ||
                      selected.parent_id}
                  </Typography>
                )}
                <Stack direction="row" gap={1} flexWrap="wrap">
                  {can(me, "nodes.manage") && (
                    <>
                      <Button onClick={() => setEdit({ ...selected })}>
                        Изменить
                      </Button>
                      <Button color="error" onClick={() => setRemove(true)}>
                        Удалить группу
                      </Button>
                    </>
                  )}
                  {can(me, "nodes.manage", selected.id) && (
                    <Button onClick={() => setMove(true)}>
                      Переместить ноды
                    </Button>
                  )}
                </Stack>
              </Stack>
            ) : (
              <Typography color="text.secondary">
                Выберите группу, чтобы посмотреть её ноды и настройки.
              </Typography>
            )}
          </Box>
        </Box>
      </Stack>
      <Dialog
        open={!!edit}
        onClose={() => setEdit(null)}
        fullWidth
        maxWidth="sm"
      >
        <DialogTitle>
          {edit?.id ? "Изменить группу" : "Создать группу"}
        </DialogTitle>
        <DialogContent>
          {edit && (
            <Stack gap={3} pt={1}>
              <TextField
                label="Название"
                value={edit.name}
                onChange={(e) => setEdit({ ...edit, name: e.target.value })}
              />
              <ResourceSelect
                resource="/groups"
                label="Родительская группа"
                value={edit.parent_id || ""}
                initialLabel={groups.find((g) => g.id === edit.parent_id)?.name}
                allowRoot
                onChange={(id) => setEdit({ ...edit, parent_id: id })}
              />
            </Stack>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEdit(null)}>Отмена</Button>
          <Button
            disabled={!edit?.name.trim()}
            onClick={() =>
              void act(() =>
                changed(async () => {
                  await api(
                    edit?.id ? `/groups/${edit.id}` : "/groups",
                    edit?.id ? "PUT" : "POST",
                    edit,
                  );
                  setEdit(null);
                }),
              )
            }
          >
            Сохранить
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog open={remove} onClose={() => setRemove(false)}>
        <DialogTitle>Удалить {selected?.name}?</DialogTitle>
        <DialogContent>
          Удалятся настройки группы и её join-токены. Ноды и дочерние группы
          нужно предварительно переместить.
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRemove(false)}>Отмена</Button>
          <Button
            color="error"
            onClick={() =>
              void act(() =>
                changed(async () => {
                  await api(`/groups/${selected!.id}`, "DELETE", undefined, {
                    confirmed: true,
                  });
                  setRemove(false);
                  setSelected(null);
                  onFilter?.("");
                }),
              )
            }
          >
            Удалить
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog
        open={move}
        onClose={() => setMove(false)}
        fullWidth
        maxWidth="md"
      >
        <DialogTitle>Переместить ноды из {selected?.name}</DialogTitle>
        <DialogContent>
          <Stack gap={2} pt={1}>
            {hosts.error && <Alert severity="error">{hosts.error}</Alert>}
            <ResourceSelect
              resource="/groups"
              label="Куда"
              value={destination}
              onChange={setDestination}
            />
            <DataTable
              heads={["", "Нода", "Синхронизация"]}
              empty={!hosts.items.length}
            >
              {hosts.items.map((n) => (
                <TableRow key={n.id}>
                  <TableCell>
                    <Checkbox
                      slotProps={{ input: { "aria-label": `Выбрать ${n.name}` } }}
                      checked={checked.has(n.id)}
                      onChange={(_, v) =>
                        setHostIDs(
                          v
                            ? [...hostIDs, n.id]
                            : hostIDs.filter((id) => id !== n.id),
                        )
                      }
                    />
                  </TableCell>
                  <TableCell>{n.name}</TableCell>
                  <TableCell>
                    <Status value={n.status} />
                  </TableCell>
                </TableRow>
              ))}
            </DataTable>
            <Pagination {...hosts} next={!!hosts.next} />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setMove(false)}>Отмена</Button>
          <Button
            disabled={!destination || !hostIDs.length || hostIDs.length > 500}
            onClick={() =>
              void act(() =>
                changed(async () => {
                  await api("/nodes/move", "POST", {
                    node_ids: hostIDs,
                    group_id: destination,
                  });
                  setHostIDs([]);
                  setMove(false);
                }),
              )
            }
          >
            Переместить ({hostIDs.length})
          </Button>
        </DialogActions>
      </Dialog>
    </Paper>
  );
}
