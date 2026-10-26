import { useEffect, useMemo, useRef, useState } from "react";
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  MenuItem,
  Paper,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import { Add, Remove, CenterFocusStrong, OpenInNew } from "@mui/icons-material";
import { apiWithCursor } from "./api";
import { Pagination, usePageNavigation } from "./Pagination";
import { useDebounced } from "./useDebounced";
import type { Role } from "./types";
import { roleSudoers } from "./Roles";
export type Connection = {
  id: string;
  subject_id: string;
  subject_name: string;
  subject_kind: string;
  group_id: string;
  group_name: string;
  ancestors: string[];
  role: Role;
};
type Recommendation = {
  kind: string;
  connections: string[];
  message: string;
  common: string[];
};
type Graph = { connections: Connection[]; recommendations: Recommendation[] };
const kinds: Record<string, string> = {
  unix_group: "UNIX-группа",
  people_group: "Группа людей",
  user: "Персональное назначение",
};
const colours = ["#eaf1ff", "#f0eaff", "#e8f4ee"];
type Vertex = {
  id: string;
  title: string;
  subtitle: string;
  column: number;
  x: number;
  y: number;
  connections: string[];
};
export function graphLayout(connections: Connection[]) {
  const vertices = new Map<string, Vertex>(),
    edges: { from: string; to: string; connections: string[] }[] = [];
  const add = (
    id: string,
    title: string,
    subtitle: string,
    column: number,
    connection: string,
  ) => {
    const old = vertices.get(id);
    if (old) {
      old.connections.push(connection);
      return;
    }
    vertices.set(id, {
      id,
      title,
      subtitle,
      column,
      x: column * 355 + 25,
      y: 0,
      connections: [connection],
    });
  };
  for (const c of connections) {
    const source = c.subject_kind + ":" + c.subject_id,
      grant =
        "grant:" +
        c.role.id +
        ":" +
        c.group_id +
        ":" +
        (c.subject_kind === "unix_group" ? "native" : "combined"),
      scope = "scope:" + c.group_id;
    add(source, c.subject_name, kinds[c.subject_kind], 0, c.id);
    add(
      grant,
      c.role.name,
      c.subject_kind === "unix_group"
        ? "Вход на ноды / sudo"
        : c.role.linux_access && c.role.permissions.length
          ? "Heimdall + UNIX"
          : c.role.linux_access
            ? "Вход на ноды / sudo"
            : "Права Heimdall",
      1,
      c.id,
    );
    add(
      scope,
      c.group_name,
      c.group_id === "*" ? "Глобальная область" : "Включая дочерние группы",
      2,
      c.id,
    );
    edges.push(
      { from: source, to: grant, connections: [c.id] },
      { from: grant, to: scope, connections: [c.id] },
    );
  }
  for (let column = 0; column < 3; column++)
    Array.from(vertices.values())
      .filter((v) => v.column === column)
      .forEach((v, i) => (v.y = 65 + i * 88));
  const merged = new Map<string, (typeof edges)[number]>();
  for (const e of edges) {
    const key = e.from + "|" + e.to,
      old = merged.get(key);
    if (old) old.connections.push(...e.connections);
    else merged.set(key, e);
  }
  const uniqueEdges = Array.from(merged.values());
  return {
    vertices: Array.from(vertices.values()),
    edges: uniqueEdges,
    height: Math.max(
      500,
      ...Array.from(vertices.values()).map((v) => v.y + 100),
    ),
  };
}
export function AccessGraph() {
  const [data, setData] = useState<Graph>({
      connections: [],
      recommendations: [],
    }),
    [error, setError] = useState(""),
    [loading, setLoading] = useState(false),
    [query, setQuery] = useState(""),
    [kind, setKind] = useState(""),
    [size, setSize] = useState(25),
    [selected, setSelected] = useState(""),
    [highlight, setHighlight] = useState<string[]>([]),
    [camera, setCamera] = useState({ x: 0, y: 0, scale: 1 });
  const search = useDebounced(query),
    pages = usePageNavigation(),
    svg = useRef<SVGSVGElement>(null),
    drag = useRef<{ x: number; y: number; camera: typeof camera } | null>(null);
  useEffect(() => pages.reset(), [search, kind, size]);
  useEffect(() => {
    let active = true;
    setLoading(true);
    void apiWithCursor<Graph>(
      `/access/graph?limit=${size}&after=${encodeURIComponent(pages.after)}&query=${encodeURIComponent(search)}&kind=${kind}`,
    )
      .then((r) => {
        if (active) {
          setData(r.data);
          pages.setNext(r.next);
          setError("");
          setSelected("");
          setHighlight([]);
          setCamera({ x: 0, y: 0, scale: 1 });
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
  }, [search, kind, size, pages.after]);
  const layout = useMemo(() => graphLayout(data.connections), [data]);
  const byID = new Map(layout.vertices.map((v) => [v.id, v])),
    vertex = byID.get(selected);
  const activeConnections = new Set(
    highlight.length ? highlight : vertex?.connections || [],
  );
  const zoom = (step: number) =>
    setCamera((c) => {
      const scale = Math.max(0.05, Math.min(3, c.scale * step));
      return {
        x: 550 - ((550 - c.x) * scale) / c.scale,
        y: 250 - ((250 - c.y) * scale) / c.scale,
        scale,
      };
    });
  useEffect(() => {
    const canvas = svg.current;
    if (!canvas) return;
    const wheel = (e: WheelEvent) => {
      const matrix = canvas.getScreenCTM();
      if (!matrix || !e.deltaY) return;
      e.preventDefault();
      const point = new DOMPoint(e.clientX, e.clientY).matrixTransform(
        matrix.inverse(),
      );
      setCamera((c) => {
        const scale = Math.max(
          0.05,
          Math.min(3, c.scale * Math.exp(-e.deltaY * 0.002)),
        );
        return {
          x: point.x - ((point.x - c.x) * scale) / c.scale,
          y: point.y - ((point.y - c.y) * scale) / c.scale,
          scale,
        };
      });
    };
    canvas.addEventListener("wheel", wheel, { passive: false });
    return () => canvas.removeEventListener("wheel", wheel);
  }, [data.connections.length]);
  const details = data.connections.filter((c) =>
    vertex?.connections.includes(c.id),
  );
  return (
    <Stack gap={3}>
      <Stack direction={{ xs: "column", sm: "row" }} gap={2}>
        <TextField
          fullWidth
          label="Поиск: участник, группа, роль"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <TextField
          select
          label="Источник назначения"
          value={kind}
          onChange={(e) => setKind(e.target.value)}
          sx={{ minWidth: 220 }}
        >
          <MenuItem value="">Все назначения</MenuItem>
          {Object.entries(kinds).map(([k, v]) => (
            <MenuItem key={k} value={k}>
              {v}
            </MenuItem>
          ))}
        </TextField>
        <TextField
          select
          label="На странице"
          value={size}
          onChange={(e) => setSize(Number(e.target.value))}
          sx={{ minWidth: 130 }}
        >
          {[10, 25, 50, 100].map((n) => (
            <MenuItem key={n} value={n}>
              {n}
            </MenuItem>
          ))}
        </TextField>
      </Stack>
      {error && <Alert severity="error">{error}</Alert>}
      <Paper className="panel" sx={{ p: 2 }}>
        <Stack
          direction="row"
          alignItems="center"
          gap={1}
          flexWrap="wrap"
          mb={1}
        >
          <Button aria-label="Увеличить граф" onClick={() => zoom(1.2)}>
            <Add />
          </Button>
          <Button aria-label="Уменьшить граф" onClick={() => zoom(1 / 1.2)}>
            <Remove />
          </Button>
          <Button
            startIcon={<CenterFocusStrong />}
            onClick={() =>
              setCamera({ x: 0, y: 0, scale: Math.min(1, 500 / layout.height) })
            }
          >
            Вместить
          </Button>
          <Button
            onClick={() => {
              setCamera({ x: 0, y: 0, scale: 1 });
              setSelected("");
              setHighlight([]);
            }}
          >
            Сбросить
          </Button>
          <Typography variant="caption">
            {data.connections.length} назначений · перетаскивайте фон · колёсико
            / +/−
          </Typography>
          {loading && <CircularProgress size={20} />}
          <Box flex={1} />
          <Button
            href="/?page=access-graph"
            target="_blank"
            rel="noopener"
            aria-label="Открыть граф в отдельной вкладке"
          >
            <OpenInNew />
          </Button>
        </Stack>
        {!data.connections.length && !loading ? (
          <Typography sx={{ p: 4 }} color="text.secondary">
            Назначений по этим фильтрам нет.
          </Typography>
        ) : (
          <svg
            ref={svg}
            viewBox="0 0 1100 500"
            width="100%"
            style={{
              height: 500,
              background: "#f8fafc",
              borderRadius: 16,
              touchAction: "none",
              cursor: drag.current ? "grabbing" : "grab",
            }}
            tabIndex={0}
            role="group"
            aria-label="Граф назначений доступа"
            onKeyDown={(e) => {
              if (e.key === "+" || e.key === "=") zoom(1.2);
              else if (e.key === "-") zoom(1 / 1.2);
              else if (e.key === "Escape") {
                setSelected("");
                setHighlight([]);
              } else if (e.key.startsWith("Arrow")) {
                e.preventDefault();
                setCamera((c) => ({
                  ...c,
                  x:
                    c.x +
                    (e.key === "ArrowLeft"
                      ? 40
                      : e.key === "ArrowRight"
                        ? -40
                        : 0),
                  y:
                    c.y +
                    (e.key === "ArrowUp"
                      ? 40
                      : e.key === "ArrowDown"
                        ? -40
                        : 0),
                }));
              }
            }}
            onPointerDown={(e) => {
              if (e.target !== e.currentTarget) return;
              drag.current = { x: e.clientX, y: e.clientY, camera };
              e.currentTarget.setPointerCapture(e.pointerId);
            }}
            onPointerMove={(e) => {
              const d = drag.current,
                rect = e.currentTarget.getBoundingClientRect();
              if (d)
                setCamera({
                  ...d.camera,
                  x: d.camera.x + ((e.clientX - d.x) * 1100) / rect.width,
                  y: d.camera.y + ((e.clientY - d.y) * 1100) / rect.width,
                });
            }}
            onPointerUp={() => (drag.current = null)}
            onPointerCancel={() => (drag.current = null)}
          >
            <defs>
              <marker
                id="access-arrow"
                markerWidth="8"
                markerHeight="8"
                refX="7"
                refY="4"
                orient="auto"
              >
                <path d="M0,0 L8,4 L0,8" fill="#8395ad" />
              </marker>
            </defs>
            <g
              transform={`translate(${camera.x},${camera.y}) scale(${camera.scale})`}
            >
              {["Кому", "Что разрешено", "Где"].map((title, i) => (
                <text
                  key={title}
                  x={25 + i * 355}
                  y={30}
                  fill="#617187"
                  fontSize={16}
                  fontWeight={600}
                >
                  {title}
                </text>
              ))}
              {layout.edges.map((e) => {
                const a = byID.get(e.from)!,
                  b = byID.get(e.to)!;
                const strong = e.connections.some((id) =>
                  activeConnections.has(id),
                );
                return (
                  <path
                    key={e.from + e.to}
                    d={`M${a.x + 285},${a.y + 30} C${a.x + 330},${a.y + 30} ${b.x - 45},${b.y + 30} ${b.x - 5},${b.y + 30}`}
                    fill="none"
                    stroke={strong ? "#155ac8" : "#b5c3d6"}
                    strokeWidth={strong ? 3 : 1.5}
                    opacity={activeConnections.size && !strong ? 0.25 : 1}
                    markerEnd="url(#access-arrow)"
                  />
                );
              })}
              {layout.vertices.map((v) => (
                <g
                  key={v.id}
                  role="button"
                  aria-label={`${v.subtitle}: ${v.title}`}
                  tabIndex={0}
                  onPointerDown={(e) => e.stopPropagation()}
                  onClick={() => {
                    setSelected(v.id);
                    setHighlight([]);
                  }}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      setSelected(v.id);
                      setHighlight([]);
                    }
                  }}
                  transform={`translate(${v.x},${v.y})`}
                  style={{ cursor: "pointer" }}
                  opacity={
                    activeConnections.size &&
                    !v.connections.some((id) => activeConnections.has(id))
                      ? 0.3
                      : 1
                  }
                >
                  <rect
                    width={285}
                    height={62}
                    rx={12}
                    fill={colours[v.column]}
                    stroke={selected === v.id ? "#155ac8" : "#cbd6e5"}
                    strokeWidth={selected === v.id ? 2 : 1}
                  />
                  <title>
                    {v.title} · {v.subtitle}
                  </title>
                  <text
                    x={14}
                    y={25}
                    fill="#172d47"
                    fontSize={15}
                    fontWeight={600}
                  >
                    {v.title.length > 32 ? v.title.slice(0, 30) + "…" : v.title}
                  </text>
                  <text x={14} y={46} fill="#617187" fontSize={12}>
                    {v.subtitle}
                  </text>
                </g>
              ))}
            </g>
          </svg>
        )}
        <Pagination {...pages.controls} />
      </Paper>
      {vertex && (
        <Paper className="panel">
          <Typography variant="h6" mb={2}>
            {vertex.title}
          </Typography>
          <Stack gap={2}>
            {details.map((c) => (
              <Box key={c.id}>
                <Typography>
                  {c.subject_name} → {c.role.name} → {c.group_name}
                </Typography>
                <Stack direction="row" gap={1} flexWrap="wrap" mt={1}>
                  {(c.subject_kind === "unix_group"
                    ? []
                    : c.role.permissions
                  ).map((p) => (
                    <Chip size="small" key={p} label={p} />
                  ))}
                  {c.role.allow_ssh_keys && (
                    <Chip size="small" label="SSH-ключи" />
                  )}
                  {c.role.allow_password && (
                    <Chip size="small" label="UNIX-пароль" />
                  )}
                </Stack>
                {roleSudoers(c.role) && (
                  <Typography
                    component="pre"
                    className="mono"
                    sx={{ whiteSpace: "pre-wrap", fontSize: 13 }}
                  >
                    {roleSudoers(c.role)}
                  </Typography>
                )}
              </Box>
            ))}
          </Stack>
        </Paper>
      )}
      <Paper className="panel">
        <Typography variant="h6" mb={2}>
          Пересечения и рекомендации
        </Typography>
        <Typography variant="body2" color="text.secondary" mb={2}>
          Анализ назначений текущей страницы. Общие права складываются;
          пересечение само по себе не является ошибкой. Произвольные
          sudoers-шаблоны и пересечения членства разных групп не анализируются.
        </Typography>
        <Stack gap={2}>
          {data.recommendations.map((r, i) => (
            <Alert
              key={i}
              severity="info"
              action={
                <Button
                  onClick={() => {
                    setHighlight(r.connections);
                    setSelected("");
                  }}
                >
                  Показать связи
                </Button>
              }
            >
              <Typography fontWeight={600}>
                {r.kind === "duplicate_role"
                  ? "Одинаковые роли"
                  : "Пересечение назначений"}
              </Typography>
              {r.connections
                .map(
                  (id) => data.connections.find((c) => c.id === id)?.role.name,
                )
                .join(" ↔ ")}
              <Typography variant="body2">{r.message}</Typography>
              <Typography variant="caption">
                Общие права: {r.common.join(", ")}
              </Typography>
            </Alert>
          ))}
          {!data.recommendations.length && (
            <Typography color="text.secondary">
              На этой странице пересечений по проверяемым правилам не найдено.
            </Typography>
          )}
        </Stack>
      </Paper>
      <Typography variant="body2" color="text.secondary">
        Граф показывает назначения, а не подтверждённые права конкретного
        пользователя. Активность учётки, членство, факторы, синхронизация и
        мандатные метки проверяются при расчёте доступа.{" "}
        <a href="/?page=docs&doc=access-management">Документация</a>
      </Typography>
    </Stack>
  );
}
