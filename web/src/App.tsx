import { useDebounced } from "./useDebounced";
import { useCallback, useEffect, useRef, useState } from "react";
import {
  Alert,
  Avatar,
  Box,
  Button,
  Chip,
  Checkbox,
  FormControlLabel,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  IconButton,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  MenuItem,
  Menu,
  Paper,
  Snackbar,
  Stack,
  TableCell,
  TableRow,
  TextField,
  Typography,
} from "@mui/material";
import {
  Add,
  ApiOutlined,
  CheckCircleOutline,
  DashboardOutlined,
  DnsOutlined,
  GroupsOutlined,
  HistoryOutlined,
  Logout,
  SecurityOutlined,
  SettingsOutlined,
  SyncOutlined,
  MenuBookOutlined,
  MoreVert,
  WarningAmberOutlined,
} from "@mui/icons-material";
import {
  api,
  page as apiPage,
  APIError,
  ActionCancelledError,
  can,
  canAny,
  date,
} from "./api";
import type {
  AuditEvent,
  Group,
  Incident,
  Me,
  Node,
  Operation,
  Role,
  SyncTarget,
  User,
} from "./types";
import { AccessConfirmation } from "./AccessConfirmation";
import { AvailableNodes } from "./AvailableNodes";
import { effectivePage, pageAllowed } from "./pageAccess";
import { Logo } from "./Logo";
import { Login } from "./Login";
import { DataTable, Status } from "./common";
import { Account } from "./Account";
import { Tokens } from "./Tokens";
import { PeopleGroups } from "./PeopleGroups";
import { SecurityEvents } from "./SecurityEvents";
import { Settings } from "./Settings";
import { ResourceSelect } from "./ResourceSelect";
import { Pagination, usePageNavigation } from "./Pagination";
import { NodeDetails } from "./NodeDetails";
import { FleetGroups } from "./FleetGroups";
import { Roles } from "./Roles";
import { AccessGraph } from "./AccessGraph";
import { AccessAssignments } from "./AccessAssignments";
import { AccessNavigation } from "./AccessNavigation";
import { Incidents } from "./Incidents";
import { UnixDirectory } from "./UnixDirectory";
import { NodeHealth } from "./NodeHealth";
import { Documentation } from "./Documentation";
import { JoinTokens } from "./JoinTokens";
import { Announcements } from "./Announcements";
import { durationSeconds } from "./duration";
import { factorPolicies } from "./factorPolicies";
import { currentPage, pageURL } from "./navigation";
type Data = {
  users: User[];
  nodes: Node[];
  groups: Group[];
  roles: Role[];
  operations: Operation[];
  incidents: Incident[];
  audit: AuditEvent[];
};
const empty: Data = {
  users: [],
  nodes: [],
  groups: [],
  roles: [],
  operations: [],
  incidents: [],
  audit: [],
};
const navigation = [
  ["overview", "Обзор", DashboardOutlined],
  ["users", "Пользователи", GroupsOutlined],
  ["people-groups", "Группы людей", GroupsOutlined],
  ["unix", "UNIX-каталог", GroupsOutlined],
  ["roles", "Доступ", SecurityOutlined],
  ["nodes", "Ноды", DnsOutlined],
  ["sync", "Синхронизация", SyncOutlined],
  ["docs", "Документация", MenuBookOutlined],
  ["tokens", "API и MCP", ApiOutlined],
  ["audit", "Аудит", HistoryOutlined],
  ["settings", "Настройки", SettingsOutlined],
] as const;
export function App() {
  return (
    <AccessConfirmation>
      <Application />
    </AccessConfirmation>
  );
}
function Application() {
  const [me, setMe] = useState<Me | null>(null),
    [loaded, setLoaded] = useState(false),
    [data, setData] = useState<Data>(empty),
    [view, setView] = useState(currentPage),
    [error, setError] = useState(""),
    [actionError, setActionError] = useState(""),
    [notice, setNotice] = useState(""),
    [updated, setUpdated] = useState<Date | null>(null),
    [selected, setSelected] = useState<User | null>(null),
    [create, setCreate] = useState(false),
    [nodeMenu, setNodeMenu] = useState<HTMLElement | null>(null),
    [invitation, setInvitation] = useState(""),
    [join, setJoin] = useState(false),
    [joinToken, setJoinToken] = useState(""),
    [joinName, setJoinName] = useState(""),
    [joinUses, setJoinUses] = useState(100),
    [joinTTL, setJoinTTL] = useState("365d"),
    [joinUnlimited, setJoinUnlimited] = useState(true),
    [operation, setOperation] = useState<Operation | null>(null),
    [targets, setTargets] = useState<SyncTarget[]>([]);
  const [profile, setProfile] = useState({
    login: "",
    display_name: "",
    require_mfa: false,
    sync_to_nodes: false,
    kind: "human",
    mfa_policy: "none",
    uid: 0,
    gid: 0,
    home: "",
    shell: "/bin/bash",
    gecos: "",
  });
  const [group, setGroup] = useState(""),
    [nodeCursors, setNodeCursors] = useState([""]),
    [nodePage, setNodePage] = useState(0),
    [nextNode, setNextNode] = useState(""),
    [userCursors, setUserCursors] = useState([""]),
    [userPage, setUserPage] = useState(0),
    [nextUser, setNextUser] = useState(""),
    [summary, setSummary] = useState({
      nodes: 0,
      healthy: 0,
      pending: 0,
      incidents: 0,
      warning: 0,
      offline: 0,
    });
  const [userSearch, setUserSearch] = useState(""),
    [userKind, setUserKind] = useState(""),
    [userStatus, setUserStatus] = useState(""),
    [userFactor, setUserFactor] = useState(""),
    [userSync, setUserSync] = useState("");
  const [userFilter, setUserFilter] = useState({
    search: "",
    kind: "",
    status: "",
    factor: "",
    sync: "",
  });
  useEffect(() => {
    if (
      userFilter.search === userSearch &&
      userFilter.kind === userKind &&
      userFilter.status === userStatus &&
      userFilter.factor === userFactor &&
      userFilter.sync === userSync
    )
      return;
    const timer = setTimeout(() => {
      setUserFilter({
        search: userSearch,
        kind: userKind,
        status: userStatus,
        factor: userFactor,
        sync: userSync,
      });
      setUserCursors([""]);
      setUserPage(0);
    }, 250);
    return () => clearTimeout(timer);
  }, [userSearch, userKind, userStatus, userFactor, userSync, userFilter]);
  const [recoveryToken, setRecoveryToken] = useState("");
  const targetPages = usePageNavigation();
  const operationPages = usePageNavigation(),
    incidentPages = usePageNavigation(),
    auditPages = usePageNavigation(),
    rolePages = usePageNavigation();
  const [roleQuery, setRoleQuery] = useState(""),
    [roleKind, setRoleKind] = useState("all");
  const [nodeQuery, setNodeQuery] = useState(""),
    [nodeGroup, setNodeGroup] = useState(""),
    [nodeStatus, setNodeStatus] = useState(""),
    [nodePlatform, setNodePlatform] = useState(""),
    [nodeDetail, setNodeDetail] = useState<Node | null>(null),
    [incidentQuery, setIncidentQuery] = useState(""),
    [auditQuery, setAuditQuery] = useState("");
  const nodeSearchQuery = useDebounced(nodeQuery),
    roleSearchQuery = useDebounced(roleQuery),
    incidentSearchQuery = useDebounced(incidentQuery),
    auditSearchQuery = useDebounced(auditQuery);
  useEffect(() => {
    rolePages.reset();
  }, [roleSearchQuery]);
  useEffect(() => {
    setNodeCursors([""]);
    setNodePage(0);
  }, [nodeSearchQuery, nodeGroup, nodeStatus, nodePlatform]);
  useEffect(() => {
    incidentPages.reset();
  }, [incidentSearchQuery]);
  useEffect(() => {
    auditPages.reset();
  }, [auditSearchQuery]);
  const requestVersion = useRef(0);
  const refresh = useCallback(async () => {
    const version = ++requestVersion.current;
    try {
      const user = await api<Me>("/me");
      if (version !== requestVersion.current) return;
      setMe(user);
      if (user.principal.restricted) {
        setView(view === "docs" ? "docs" : "account");
        setData(empty);
        setError("");
        setUpdated(new Date());
        return;
      }
      const any = (p: string) => canAny(user, p);
      const currentView = effectivePage(user, view);
      const [users, nodes, groups, roles, operations, incidents, audit] =
        await Promise.all([
          currentView === "users" && any("users.read")
            ? apiPage<User>(
                "/users?limit=100&after=" +
                  userCursors[userPage] +
                  "&query=" +
                  encodeURIComponent(userFilter.search) +
                  "&kind=" +
                  userFilter.kind +
                  "&status=" +
                  userFilter.status +
                  "&factor=" +
                  userFilter.factor +
                  "&unix_sync=" +
                  userFilter.sync,
              )
            : { items: [], next: "" },
          ["overview", "nodes"].includes(currentView) && any("nodes.read")
            ? apiPage<Node>(
                "/nodes?limit=100&after=" +
                  nodeCursors[nodePage] +
                  "&query=" +
                  encodeURIComponent(nodeSearchQuery) +
                  "&group_id=" +
                  encodeURIComponent(nodeGroup) +
                  "&status=" +
                  nodeStatus +
                  "&platform=" +
                  nodePlatform,
              )
            : { items: [], next: "" },
          ["nodes", "users", "roles", "join-tokens"].includes(currentView) &&
          (any("nodes.read") || any("nodes.manage") || any("roles.manage"))
            ? api<Group[]>("/groups")
            : [],
          currentView === "roles" && (any("roles.read") || any("roles.manage"))
            ? apiPage<Role>(
                "/roles?limit=100&after=" +
                  encodeURIComponent(rolePages.after) +
                  "&query=" +
                  encodeURIComponent(roleSearchQuery) +
                  "&status=" +
                  roleKind,
              )
            : { items: [], next: "" },
          currentView === "sync" && any("sync.read")
            ? apiPage<Operation>(
                "/operations?limit=100&after=" +
                  encodeURIComponent(operationPages.after),
              )
            : { items: [], next: "" },
          ["overview", "sync"].includes(currentView) && any("incidents.read")
            ? apiPage<Incident>(
                "/incidents?limit=100&after=" +
                  encodeURIComponent(incidentPages.after) +
                  "&query=" +
                  encodeURIComponent(incidentSearchQuery),
              )
            : { items: [], next: "" },
          currentView === "audit" && any("audit.read")
            ? apiPage<AuditEvent>(
                "/audit?limit=100&after=" +
                  encodeURIComponent(auditPages.after) +
                  "&query=" +
                  encodeURIComponent(auditSearchQuery),
              )
            : { items: [], next: "" },
        ]);
      const counts =
        ["overview", "nodes"].includes(currentView) && any("nodes.read")
          ? await api<typeof summary>("/summary")
          : {
              nodes: 0,
              healthy: 0,
              pending: 0,
              incidents: 0,
              warning: 0,
              offline: 0,
            };
      if (version !== requestVersion.current) return;
      setData({
        users: users.items,
        nodes: nodes.items,
        groups,
        roles: roles.items,
        operations: operations.items,
        incidents: incidents.items,
        audit: audit.items,
      });
      rolePages.setNext(roles.next);
      operationPages.setNext(operations.next);
      incidentPages.setNext(incidents.next);
      auditPages.setNext(audit.next);
      setNextNode(nodes.next);
      setNextUser(users.next);
      setSummary(counts);
      setSelected((current) =>
        current
          ? users.items.find((u) => u.id === current.id) || current
          : null,
      );
      setUpdated(new Date());
      setError("");
    } catch (e) {
      if (version !== requestVersion.current) return;
      if (e instanceof APIError && e.status === 401) setMe(null);
      else setError("Не удалось обновить данные: " + (e as Error).message);
    } finally {
      if (version === requestVersion.current) setLoaded(true);
    }
  }, [
    nodePage,
    userPage,
    nodeCursors,
    userCursors,
    userFilter,
    nodeSearchQuery,
    nodeGroup,
    nodeStatus,
    nodePlatform,
    operationPages.after,
    incidentPages.after,
    auditPages.after,
    incidentSearchQuery,
    auditSearchQuery,
    rolePages.after,
    roleSearchQuery,
    roleKind,
    view,
  ]);
  useEffect(() => {
    void refresh();
    return () => {
      requestVersion.current++;
    };
  }, [refresh]);
  const latestRefresh = useRef(refresh);
  latestRefresh.current = refresh;
  const fleetEventsAllowed =
    !!me &&
    !me.principal.restricted &&
    (canAny(me, "nodes.read") || canAny(me, "sync.read"));
  useEffect(() => {
    if (
      typeof EventSource === "undefined" ||
      !fleetEventsAllowed ||
      !["overview", "nodes", "sync", "settings"].includes(view)
    )
      return;
    let source: EventSource | null = null;
    let pending: ReturnType<typeof setTimeout> | undefined;
    const connect = () => {
      source?.close();
      source = null;
      if (document.visibilityState === "hidden") return;
      source = new EventSource("/api/v1/events/fleet");
      let interrupted = false;
      const invalidate = () => {
        clearTimeout(pending);
        pending = setTimeout(() => void latestRefresh.current(), 400);
      };
      source.addEventListener("fleet", invalidate);
      source.addEventListener("error", () => {
        interrupted = true;
      });
      source.addEventListener("open", () => {
        // Events can be missed while disconnected; reconcile the visible page
        // when the stream recovers, without an idle catalogue polling loop.
        if (interrupted) {
          interrupted = false;
          invalidate();
        }
      });
    };
    const visible = () => {
      connect();
      if (document.visibilityState !== "hidden") void latestRefresh.current();
    };
    connect();
    document.addEventListener("visibilitychange", visible);
    return () => {
      source?.close();
      clearTimeout(pending);
      document.removeEventListener("visibilitychange", visible);
    };
  }, [fleetEventsAllowed, view, me?.user.id]);
  useEffect(() => {
    const onPopState = () => setView(currentPage());
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);
  function navigate(id: string) {
    history.pushState({}, "", pageURL(id));
    setView(id);
  }
  async function act(fn: () => Promise<unknown>) {
    try {
      await fn();
      setNotice("Изменения сохранены.");
      await refresh();
    } catch (e) {
      if (e instanceof ActionCancelledError) return;
      setActionError((e as Error).message);
    }
  }
  useEffect(() => {
    if (!operation) return;
    let active = true;
    void apiPage<SyncTarget>(
      `/operations/${operation.id}/targets?after=${encodeURIComponent(targetPages.after)}`,
    )
      .then((result) => {
        if (active) {
          setTargets(result.items);
          targetPages.setNext(result.next);
        }
      })
      .catch((e) => {
        if (active) setActionError(e.message);
      });
    return () => {
      active = false;
    };
  }, [operation?.id, targetPages.after]);
  if (location.pathname === "/invite")
    return (
      <Login
        onLogin={() => {
          setView(currentPage());
          void refresh();
        }}
      />
    );
  if (!loaded)
    return (
      <Box sx={{ p: 6 }}>
        <Typography>Heimdall · подключаемся…</Typography>
      </Box>
    );
  if (!me)
    return (
      <>
        {" "}
        {error && <Alert severity="error">{error}</Alert>}{" "}
        <Login onLogin={() => void refresh()} />{" "}
      </>
    );
  const allowed = (v: string) => pageAllowed(me, v);
  const nav = navigation.filter(
    ([id]) =>
      (allowed(id) || (id === "roles" && allowed("access-assignments"))) &&
      (id !== "nodes" || canAny(me, "nodes.read")),
  );
  const activeNav =
    nav.find(
      (n) =>
        n[0] ===
        (["access-assignments", "access-graph"].includes(view)
          ? "roles"
          : view),
    ) || nav[0];
  const page = effectivePage(me, view);
  const fleetReader = canAny(me, "nodes.read");
  const healthy = summary.healthy,
    incidents = data.incidents.filter((i) => i.status !== "resolved");
  const openOperation = (o: Operation) => {
    targetPages.reset();
    setTargets([]);
    setOperation(o);
  };
  return (
    <>
      <Paper className="sidebar">
        <Stack direction="row" alignItems="center" gap={1} px={1} mb={4}>
          <Logo size={36} />
          <Typography variant="h5">Heimdall</Typography>
        </Stack>
        <List sx={{ p: 0, overflowY: "auto", flex: 1, minHeight: 0 }}>
          {nav.map(([id, label, Icon]) => (
            <ListItemButton
              key={id}
              className="nav-item"
              selected={
                page === id ||
                (page === "join-tokens" && id === "nodes") ||
                (["access-assignments", "access-graph"].includes(page) &&
                  id === "roles")
              }
              href={pageURL(
                id === "roles" && !allowed("roles") ? "access-assignments" : id,
              )}
              onClick={(event) => {
                if (event.ctrlKey || event.metaKey || event.shiftKey) return;
                event.preventDefault();
                navigate(
                  id === "roles" && !allowed("roles")
                    ? "access-assignments"
                    : id,
                );
              }}
            >
              <ListItemIcon sx={{ minWidth: 38, color: "inherit" }}>
                <Icon />
              </ListItemIcon>
              <ListItemText
                primary={id === "overview" && !fleetReader ? "Ноды" : label}
                primaryTypographyProps={{
                  fontSize: 14,
                  fontWeight: page === id ? 650 : 500,
                }}
              />
            </ListItemButton>
          ))}
        </List>
        <Divider sx={{ my: 2 }} />
        <Stack direction="row" gap={1.5} alignItems="center" px={1}>
          <ListItemButton
            aria-label="Открыть профиль"
            selected={page === "account"}
            href={pageURL("account")}
            onClick={(event) => {
              if (event.ctrlKey || event.metaKey || event.shiftKey) return;
              event.preventDefault();
              navigate("account");
            }}
            sx={{ borderRadius: 2, p: 0.5, gap: 1.5 }}
          >
            <Avatar
              sx={{
                bgcolor: "#d7e5fd",
                color: "#17447f",
                width: 36,
                height: 36,
              }}
            >
              {me.user.login[0].toUpperCase()}
            </Avatar>
            <Box flex={1}>
              <Typography fontSize={14} fontWeight={650}>
                {me.user.login}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                {can(me, "users.manage") ? "Администратор" : "Пользователь"}
              </Typography>
            </Box>
          </ListItemButton>
          <IconButton
            size="small"
            aria-label="Выйти"
            onClick={() =>
              void act(async () => {
                await api("/auth/logout", "POST", {});
                setMe(null);
              })
            }
          >
            <Logout fontSize="small" />
          </IconButton>
        </Stack>
      </Paper>
      <Box className="content">
        <Stack
          className="mobile-brand"
          direction="row"
          alignItems="center"
          gap={1}
          mb={2}
        >
          <Logo size={32} />
          <Typography variant="h5">Heimdall</Typography>
          <Box flex={1} />
          <Button
            href={pageURL("account")}
            onClick={(e) => {
              e.preventDefault();
              navigate("account");
            }}
          >
            {me.user.login}
          </Button>
          <IconButton
            aria-label="Выйти"
            onClick={() =>
              void act(async () => {
                await api("/auth/logout", "POST", {});
                setMe(null);
              })
            }
          >
            <Logout />
          </IconButton>
        </Stack>
        <Box className="mobile-menu">
          {nav.map(([id, label]) => (
            <Button
              key={id}
              variant={
                page === id ||
                (id === "roles" &&
                  ["access-assignments", "access-graph"].includes(page))
                  ? "contained"
                  : "text"
              }
              href={pageURL(
                id === "roles" && !allowed("roles") ? "access-assignments" : id,
              )}
              onClick={(event) => {
                if (event.ctrlKey || event.metaKey || event.shiftKey) return;
                event.preventDefault();
                navigate(
                  id === "roles" && !allowed("roles")
                    ? "access-assignments"
                    : id,
                );
              }}
              sx={{ whiteSpace: "nowrap" }}
            >
              {id === "overview" && !fleetReader ? "Ноды" : label}
            </Button>
          ))}
          <IconButton
            aria-label="Выйти"
            onClick={() =>
              void act(async () => {
                await api("/auth/logout", "POST", {});
                setMe(null);
              })
            }
          >
            <Logout />
          </IconButton>
        </Box>
        <Box className="page-top">
          <Box>
            <Typography variant="h4">
              {page === "overview" && !fleetReader
                ? "Доступные ноды"
                : page === "nodes" && !fleetReader
                  ? "Доступные ноды"
                  : page === "account"
                    ? "Профиль"
                    : page === "join-tokens"
                      ? "Токены присоединения"
                      : [
                            "roles",
                            "access-assignments",
                            "access-graph",
                          ].includes(page)
                        ? (
                            {
                              roles: "Роли",
                              "access-assignments": "Назначения доступа",
                              "access-graph": "Граф доступов",
                            } as Record<string, string>
                          )[page]
                        : activeNav?.[1]}
            </Typography>
          </Box>
        </Box>
        {error && (
          <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError("")}>
            {error}
            <br />
            Последнее успешное обновление:{" "}
            {updated?.toLocaleTimeString("ru-RU") || "не было"}. Показанные
            данные могут быть устаревшими.
          </Alert>
        )}
        {me.principal.restricted && (
          <Alert severity="warning" sx={{ mb: 3 }}>
            Требуется регистрация факторов:{" "}
            {me.factor_state?.required
              .map(
                (policy) =>
                  factorPolicies[policy as keyof typeof factorPolicies] ||
                  policy,
              )
              .join(", ") || "TOTP или passkey"}
            .
          </Alert>
        )}
        {page === "overview" && (
          <>
            <Announcements me={me} updated={updated} act={act} />
            {fleetReader && (
              <Box className="metric-grid">
                {[
                  [summary.nodes, "Подключено нод", DnsOutlined],
                  [healthy, "На связи и синхронизированы", CheckCircleOutline],
                  [
                    summary.warning,
                    "Нарушена синхронизация",
                    WarningAmberOutlined,
                  ],
                  [summary.offline, "Нет связи / отключены", DnsOutlined],
                ].map(([value, label, Icon]) => {
                  const I = Icon as typeof DnsOutlined;
                  return (
                    <Paper key={String(label)} className="metric">
                      <Stack direction="row" justifyContent="space-between">
                        <Typography color="text.secondary" fontSize={13}>
                          {String(label)}
                        </Typography>
                        <I color="primary" fontSize="small" />
                      </Stack>
                      <Typography variant="h3" fontWeight={700} mt={2}>
                        {String(value)}
                      </Typography>
                    </Paper>
                  );
                })}
              </Box>
            )}
            {canAny(me, "incidents.read") && (
              <>
                <Typography variant="h6" mb={2}>
                  Последние инциденты
                </Typography>
                <TextField
                  label="Поиск инцидентов"
                  value={incidentQuery}
                  onChange={(e) => setIncidentQuery(e.target.value)}
                  sx={{ mb: 2 }}
                />
                <Incidents
                  incidents={incidents}
                  nodes={data.nodes}
                  me={me}
                  act={act}
                />
                <Pagination {...incidentPages.controls} />
              </>
            )}
            {fleetReader ? (
              <>
                <Typography variant="h6" mt={4} mb={2}>
                  Ноды
                </Typography>
                {nodeTable(data.nodes, false)}
                <Pagination
                  index={nodePage}
                  next={!!nextNode}
                  previous={() => setNodePage((i) => Math.max(0, i - 1))}
                  advance={() => {
                    setNodeCursors((old) => [
                      ...old.slice(0, nodePage + 1),
                      nextNode,
                    ]);
                    setNodePage((i) => i + 1);
                  }}
                />
              </>
            ) : (
              <AvailableNodes version={updated?.getTime()} />
            )}
          </>
        )}
        {page === "users" && (
          <>
            <Stack direction="row" justifyContent="space-between" mb={3}>
              <Typography color="text.secondary">
                {data.users.length} учётных записей на странице
              </Typography>
              {can(me, "users.manage") && (
                <Button
                  variant="contained"
                  startIcon={<Add />}
                  onClick={() => setCreate(true)}
                >
                  Создать пользователя
                </Button>
              )}
            </Stack>
            <Stack direction="row" gap={2} mb={2}>
              <TextField
                label="Поиск пользователей: логин или имя"
                value={userSearch}
                onChange={(e) => setUserSearch(e.target.value)}
                size="small"
                fullWidth
              />
              <TextField
                select
                label="Тип УЗ"
                value={userKind}
                onChange={(e) => setUserKind(e.target.value)}
                size="small"
                sx={{ minWidth: 180 }}
              >
                <MenuItem value="">Все</MenuItem>
                <MenuItem value="human">Пользователи</MenuItem>
                <MenuItem value="service">Сервисные</MenuItem>
              </TextField>
            </Stack>
            <Stack direction={{ xs: "column", sm: "row" }} gap={2} mb={2}>
              <TextField
                select
                label="Статус пользователя"
                value={userStatus}
                onChange={(e) => setUserStatus(e.target.value)}
                sx={{ minWidth: 200 }}
              >
                <MenuItem value="">Все статусы</MenuItem>
                <MenuItem value="active">Активные</MenuItem>
                <MenuItem value="invited">Приглашённые</MenuItem>
                <MenuItem value="disabled">Заблокированные</MenuItem>
              </TextField>
              <TextField
                select
                label="Факторы входа"
                value={userFactor}
                onChange={(e) => setUserFactor(e.target.value)}
                sx={{ minWidth: 220 }}
              >
                <MenuItem value="">Все пользователи</MenuItem>
                <MenuItem value="totp">TOTP подключён</MenuItem>
                <MenuItem value="passkey">Passkey подключён</MenuItem>
                <MenuItem value="missing">Не выполнена политика</MenuItem>
                <MenuItem value="none">Факторы не подключены</MenuItem>
              </TextField>
              <TextField
                select
                label="UNIX-синхронизация"
                value={userSync}
                onChange={(e) => setUserSync(e.target.value)}
                sx={{ minWidth: 210 }}
              >
                <MenuItem value="">Любая</MenuItem>
                <MenuItem value="enabled">Включена</MenuItem>
                <MenuItem value="disabled">Выключена</MenuItem>
              </TextField>
              <Button
                onClick={() => {
                  setUserStatus("");
                  setUserFactor("");
                  setUserSync("");
                  setUserSearch("");
                  setUserKind("");
                }}
              >
                Сбросить фильтры
              </Button>
            </Stack>
            <DataTable
              heads={["Пользователь", "Статус", "POSIX", "Факторы входа", ""]}
              empty={!data.users.length}
            >
              {data.users.map((u) => (
                <TableRow key={u.id} hover>
                  <TableCell>
                    <Stack direction="row" gap={1.5} alignItems="center">
                      <Avatar
                        sx={{
                          width: 36,
                          height: 36,
                          bgcolor: "#edf2fa",
                          color: "#405373",
                        }}
                      >
                        {u.login[0].toUpperCase()}
                      </Avatar>
                      <Box>
                        <Typography fontWeight={600}>
                          {u.display_name || u.login}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {u.login} · {u.source}
                        </Typography>
                      </Box>
                    </Stack>
                  </TableCell>
                  <TableCell>
                    <Status value={u.status} />
                  </TableCell>
                  <TableCell>
                    <Typography className="mono" fontSize={13}>
                      {u.uid}:{u.gid}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {u.shell}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    {u.mfa_enabled ? (
                      <Chip
                        size="small"
                        label="MFA настроен"
                        color="success"
                        variant="outlined"
                      />
                    ) : u.require_mfa ? (
                      <Chip
                        size="small"
                        label="MFA обязателен"
                        color="warning"
                        variant="outlined"
                      />
                    ) : (
                      "Не настроены"
                    )}
                  </TableCell>
                  <TableCell>
                    <Button onClick={() => setSelected(u)}>Открыть</Button>
                  </TableCell>
                </TableRow>
              ))}
            </DataTable>
            <Stack direction="row" justifyContent="flex-end" gap={1} mt={2}>
              <Button
                disabled={!userPage}
                onClick={() => setUserPage(userPage - 1)}
              >
                Назад
              </Button>
              <Typography sx={{ p: 1 }}>Страница {userPage + 1}</Typography>
              <Button
                disabled={!nextUser}
                onClick={() => {
                  setUserCursors([
                    ...userCursors.slice(0, userPage + 1),
                    nextUser,
                  ]);
                  setUserPage(userPage + 1);
                }}
              >
                Далее
              </Button>
            </Stack>
          </>
        )}
        {page === "nodes" && !fleetReader && (
          <AvailableNodes version={updated?.getTime()} />
        )}
        {page === "nodes" && fleetReader && (
          <>
            <Stack direction="row" gap={2} justifyContent="flex-end" mb={3}>
              {can(me, "nodes.manage") && (
                <>
                  <Button
                    variant="contained"
                    startIcon={<Add />}
                    onClick={() => {
                      setGroup(data.groups[0]?.id || "");
                      setJoin(true);
                    }}
                  >
                    Подключить ноду
                  </Button>
                </>
              )}
            </Stack>
            {canAny(me, "nodes.manage") && (
              <Stack direction="row" justifyContent="flex-end" mb={2}>
                <Button
                  endIcon={<MoreVert />}
                  onClick={(e) => setNodeMenu(e.currentTarget)}
                >
                  Управление
                </Button>
              </Stack>
            )}
            <Menu
              anchorEl={nodeMenu}
              open={!!nodeMenu}
              onClose={() => setNodeMenu(null)}
            >
              <MenuItem
                onClick={() => {
                  setNodeMenu(null);
                  navigate("join-tokens");
                }}
              >
                Токены присоединения
              </MenuItem>
            </Menu>
            <FleetGroups
              me={me}
              groups={data.groups}
              act={act}
              onFilter={setNodeGroup}
            />
            <TextField
              fullWidth
              label="Поиск нод: имя, hostname, IP"
              value={nodeQuery}
              onChange={(e) => setNodeQuery(e.target.value)}
              sx={{ mb: 2 }}
            />
            <Stack direction={{ xs: "column", sm: "row" }} gap={2} mb={2}>
              <TextField
                select
                label="Состояние"
                value={nodeStatus}
                onChange={(e) => setNodeStatus(e.target.value)}
                sx={{ minWidth: 240 }}
              >
                <MenuItem value="">Все состояния</MenuItem>
                <MenuItem value="healthy">Синхронизирована</MenuItem>
                <MenuItem value="warning">Нарушена синхронизация</MenuItem>
                <MenuItem value="offline">Offline</MenuItem>
                <MenuItem value="disabled">Отключена</MenuItem>
              </TextField>
              <TextField
                select
                label="ОС"
                value={nodePlatform}
                onChange={(e) => setNodePlatform(e.target.value)}
                sx={{ minWidth: 160 }}
              >
                <MenuItem value="">Все ОС</MenuItem>
                <MenuItem value="linux">Linux</MenuItem>
                <MenuItem value="freebsd">FreeBSD</MenuItem>
              </TextField>
              <Button
                onClick={() => {
                  setNodeStatus("");
                  setNodePlatform("");
                  setNodeGroup("");
                  setNodeQuery("");
                }}
              >
                Сбросить фильтры
              </Button>
            </Stack>
            <Stack direction="row" gap={1} flexWrap="wrap" mb={2}>
              <Chip
                size="small"
                color="success"
                variant="outlined"
                label={`Синхронизированы: ${summary.healthy}`}
              />
              <Chip
                size="small"
                color="warning"
                variant="outlined"
                label={`Синхронизация нарушена: ${summary.warning}`}
              />
              <Chip
                size="small"
                color="error"
                variant="outlined"
                label={`Нет связи / отключены: ${summary.offline}`}
              />
            </Stack>
            {nodeTable(data.nodes, true)}
            <Stack direction="row" justifyContent="flex-end" gap={1} mt={2}>
              <Button
                disabled={!nodePage}
                onClick={() => setNodePage(nodePage - 1)}
              >
                Назад
              </Button>
              <Typography sx={{ p: 1 }}>
                Страница {nodePage + 1} · {`На странице ${data.nodes.length}`}
              </Typography>
              <Button
                disabled={!nextNode}
                onClick={() => {
                  setNodeCursors([
                    ...nodeCursors.slice(0, nodePage + 1),
                    nextNode,
                  ]);
                  setNodePage(nodePage + 1);
                }}
              >
                Далее
              </Button>
            </Stack>
          </>
        )}
        {["roles", "access-assignments", "access-graph"].includes(page) && (
          <AccessNavigation me={me} page={page} />
        )}
        {page === "access-graph" && <AccessGraph />}
        {page === "access-assignments" && (
          <AccessAssignments me={me} act={act} />
        )}
        {page === "roles" && (
          <>
            <TextField
              fullWidth
              label="Поиск ролей"
              value={roleQuery}
              onChange={(e) => setRoleQuery(e.target.value)}
              sx={{ mb: 2 }}
            />
            <Roles
              kind={roleKind}
              onKindChange={(kind) => {
                setRoleKind(kind);
                rolePages.reset();
              }}
              me={me}
              roles={data.roles}
              groups={data.groups}
              users={data.users}
              act={act}
            />
            <Pagination {...rolePages.controls} />
          </>
        )}
        {page === "sync" && (
          <>
            <Paper className="panel" sx={{ mb: 3 }}>
              <Stack direction="row" gap={2} alignItems="center">
                <SyncOutlined color="primary" />
                <Typography>
                  Операция завершена, когда все целевые ноды подтвердили
                  применение. Heartbeat показывает доступность агента, а ACK —
                  применение конкретной ревизии.
                </Typography>
              </Stack>
            </Paper>
            <DataTable
              heads={["Изменение", "Статус", "Применено на нодах", "Время", ""]}
              empty={!data.operations.length}
            >
              {data.operations.map((o) => (
                <TableRow key={o.id}>
                  <TableCell>
                    <Typography fontWeight={600}>{o.kind}</Typography>
                    <Typography
                      variant="caption"
                      className="mono"
                      color="text.secondary"
                    >
                      {o.id.slice(0, 8)}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Status value={o.status} />
                  </TableCell>
                  <TableCell>
                    {o.applied} / {o.total}
                    <Box className="sync-bar">
                      <Box
                        sx={{
                          width: `${o.total ? (100 * o.applied) / o.total : 100}%`,
                        }}
                      />
                    </Box>
                  </TableCell>
                  <TableCell>{date(o.created_at)}</TableCell>
                  <TableCell>
                    <Button onClick={() => void openOperation(o)}>
                      Детали
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </DataTable>
          </>
        )}
        {page === "sync" && <Pagination {...operationPages.controls} />}
        {page === "people-groups" && (
          <PeopleGroups
            me={me}
            roles={data.roles}
            groups={data.groups}
            act={act}
          />
        )}
        {page === "unix" && (
          <UnixDirectory
            me={me}
            roles={data.roles}
            groups={data.groups}
            act={act}
          />
        )}
        {nodeDetail && (
          <NodeDetails
            key={nodeDetail.id}
            node={nodeDetail}
            me={me}
            close={() => setNodeDetail(null)}
            act={act}
          />
        )}
        {page === "join-tokens" && (
          <>
            <Stack
              direction="row"
              gap={2}
              justifyContent="space-between"
              mb={2}
            >
              <Button
                href={pageURL("nodes")}
                onClick={(e) => {
                  e.preventDefault();
                  navigate("nodes");
                }}
              >
                К списку нод
              </Button>
              <Button
                variant="contained"
                startIcon={<Add />}
                onClick={() => {
                  setGroup("");
                  setJoin(true);
                }}
              >
                Выпустить токен
              </Button>
            </Stack>
            <JoinTokens me={me} groups={data.groups} act={act} />
          </>
        )}
        {page === "docs" && <Documentation me={me} act={act} />}
        {page === "account" && (
          <Account
            me={me}
            user={me.user}
            groups={data.groups}
            roles={data.roles}
            act={act}
          />
        )}
        {page === "settings" && <Settings act={act} updated={updated?.getTime()} />}
        {page === "tokens" && <Tokens me={me} groups={data.groups} act={act} />}
        {page === "audit" && can(me, "security.read") && <SecurityEvents />}
        {page === "audit" && (
          <>
            <TextField
              fullWidth
              label="Поиск в аудите"
              value={auditQuery}
              onChange={(e) => setAuditQuery(e.target.value)}
              sx={{ mb: 2 }}
            />
            <DataTable
              heads={["Действие", "Инициатор", "Канал", "Объект", "Время"]}
              empty={!data.audit.length}
            >
              {data.audit.map((e) => (
                <TableRow key={e.id}>
                  <TableCell>{e.action}</TableCell>
                  <TableCell className="mono">{e.actor_id}</TableCell>
                  <TableCell>{e.channel}</TableCell>
                  <TableCell className="mono">{e.resource_id}</TableCell>
                  <TableCell>{date(e.created_at)}</TableCell>
                </TableRow>
              ))}
            </DataTable>
            <Pagination {...auditPages.controls} />
          </>
        )}
      </Box>
      <Dialog
        open={create}
        onClose={() => setCreate(false)}
        fullWidth
        maxWidth="sm"
      >
        <DialogTitle>Новый пользователь</DialogTitle>
        <DialogContent>
          <Stack gap={2} pt={1}>
            <TextField
              label="Логин UNIX"
              value={profile.login}
              onChange={(e) =>
                setProfile({ ...profile, login: e.target.value })
              }
            />
            <TextField
              label="Отображаемое имя"
              value={profile.display_name}
              onChange={(e) =>
                setProfile({ ...profile, display_name: e.target.value })
              }
            />
            <TextField
              select
              label="Тип учётной записи"
              value={profile.kind}
              onChange={(e) =>
                setProfile({
                  ...profile,
                  kind: e.target.value,
                  require_mfa: false,
                  mfa_policy: "none",
                })
              }
            >
              <MenuItem value="human">Пользователь</MenuItem>
              <MenuItem value="service">Сервисная учётная запись</MenuItem>
            </TextField>
            <FormControlLabel
              label="Синхронизировать UNIX-учётку на ноды"
              control={
                <Checkbox
                  checked={profile.sync_to_nodes}
                  onChange={(_, checked) =>
                    setProfile({ ...profile, sync_to_nodes: checked })
                  }
                />
              }
            />
            {profile.kind !== "service" && (
              <TextField
                select
                label="Политика регистрации факторов"
                value={profile.mfa_policy}
                onChange={(e) =>
                  setProfile({
                    ...profile,
                    mfa_policy: e.target.value,
                    require_mfa: e.target.value !== "none",
                  })
                }
              >
                {Object.entries({
                  none: "Опционально",
                  any: "TOTP или passkey",
                  totp: "TOTP",
                  passkey: "Passkey",
                  both: "TOTP и passkey",
                }).map(([key, label]) => (
                  <MenuItem key={key} value={key}>
                    {label}
                  </MenuItem>
                ))}
              </TextField>
            )}
            <Stack direction="row" gap={2}>
              <TextField
                label="UID · 0 = автоматически"
                type="number"
                value={profile.uid}
                onChange={(e) =>
                  setProfile({ ...profile, uid: Number(e.target.value) })
                }
              />
              <TextField
                label="GID · 0 = автоматически"
                type="number"
                value={profile.gid}
                onChange={(e) =>
                  setProfile({ ...profile, gid: Number(e.target.value) })
                }
              />
            </Stack>
            <TextField
              label="Домашний каталог · пусто = /home/login"
              value={profile.home}
              onChange={(e) => setProfile({ ...profile, home: e.target.value })}
            />
            <TextField
              select
              label="Shell"
              value={profile.shell}
              onChange={(e) =>
                setProfile({ ...profile, shell: e.target.value })
              }
            >
              {["/bin/bash", "/bin/sh", "/usr/sbin/nologin"].map((v) => (
                <MenuItem key={v} value={v}>
                  {v}
                </MenuItem>
              ))}
            </TextField>
            <TextField
              label="GECOS"
              value={profile.gecos}
              onChange={(e) =>
                setProfile({ ...profile, gecos: e.target.value })
              }
            />
            <Alert severity="info">
              Пароль не задаётся администратором. Пользователь получит
              одноразовую ссылку первого входа на 24 часа.
            </Alert>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreate(false)}>Отмена</Button>
          <Button
            variant="contained"
            onClick={() =>
              void act(async () => {
                const r = await api<{ invitation_url: string }>(
                  "/users",
                  "POST",
                  profile,
                );
                setCreate(false);
                setInvitation(r.invitation_url);
              })
            }
          >
            Создать
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog open={!!invitation} onClose={() => setInvitation("")} fullWidth>
        <DialogTitle>Ссылка первого входа</DialogTitle>
        <DialogContent>
          <Alert severity="success" sx={{ mb: 2 }}>
            Пользователь создан. Передайте ссылку только адресату.
          </Alert>
          <TextField
            value={invitation}
            multiline
            InputProps={{ readOnly: true }}
          />
        </DialogContent>
        <DialogActions>
          <Button
            onClick={() => void navigator.clipboard.writeText(invitation)}
          >
            Копировать
          </Button>
          <Button onClick={() => setInvitation("")}>Готово</Button>
        </DialogActions>
      </Dialog>
      <Dialog
        open={join}
        onClose={() => {
          setJoin(false);
          setJoinToken("");
        }}
        fullWidth
      >
        <DialogTitle>Токен присоединения</DialogTitle>
        <DialogContent>
          <Stack gap={2} pt={1}>
            {!joinToken && (
              <TextField
                label="Название токена (необязательно)"
                value={joinName}
                onChange={(e) => setJoinName(e.target.value)}
                inputProps={{ maxLength: 120 }}
              />
            )}
            <ResourceSelect
              resource="/groups"
              label="Группа нод"
              value={group}
              onChange={setGroup}
              initialLabel={data.groups.find((g) => g.id === group)?.name}
            />
            {!joinToken && (
              <Stack direction={{ xs: "column", sm: "row" }} gap={3}>
                <FormControlLabel
                  label="Без лимита присоединений"
                  control={
                    <Checkbox
                      checked={joinUnlimited}
                      onChange={(_, checked) => setJoinUnlimited(checked)}
                    />
                  }
                />
                <TextField
                  disabled={joinUnlimited}
                  label="Лимит присоединений"
                  type="number"
                  value={joinUses}
                  onChange={(e) => setJoinUses(Number(e.target.value))}
                  slotProps={{ htmlInput: { min: 1, max: 1000000000 } }}
                />
                <TextField
                  label="Срок жизни токена"
                  value={joinTTL}
                  onChange={(e) => setJoinTTL(e.target.value)}
                  helperText="Например: 60m, 24h, 365d. До 3650 дней."
                />
              </Stack>
            )}
            {joinToken ? (
              <>
                <Alert severity="info">
                  {joinUnlimited
                    ? "Неограниченные присоединения"
                    : `До ${joinUses} присоединений`}
                  , срок действия {joinTTL}. CA и ключ проверки состояния
                  передайте на ноду доверенным способом.
                </Alert>
                <TextField
                  label="Join token"
                  multiline
                  value={joinToken}
                  InputProps={{ readOnly: true }}
                />
                <Typography variant="body2">
                  Запустите heimdall-agent с правами root на ноде, передав токен
                  через HEIMDALL_JOIN_TOKEN и адрес control plane.
                </Typography>
              </>
            ) : (
              <Typography color="text.secondary">
                Присоединённая нода далее использует собственный сертификат.
              </Typography>
            )}
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button
            onClick={() => {
              setJoin(false);
              setJoinToken("");
            }}
          >
            Закрыть
          </Button>
          {!joinToken && (
            <Button
              variant="contained"
              onClick={() =>
                void act(async () => {
                  const r = await api<{ token: string }>(
                    "/join-tokens",
                    "POST",
                    {
                      group_id: group,
                      name: joinName,
                      max_uses: joinUnlimited ? 0 : joinUses,
                      ttl_seconds: durationSeconds(joinTTL),
                    },
                  );
                  setJoinToken(r.token);
                })
              }
            >
              Выпустить токен
            </Button>
          )}
        </DialogActions>
      </Dialog>
      <Dialog
        open={!!selected}
        onClose={() => setSelected(null)}
        fullWidth
        maxWidth="md"
      >
        <DialogTitle>{selected?.display_name || selected?.login}</DialogTitle>
        <DialogContent>
          {selected && (
            <Account
              me={me}
              user={selected}
              groups={data.groups}
              roles={data.roles}
              act={act}
            />
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setSelected(null)}>Закрыть</Button>
        </DialogActions>
      </Dialog>
      <Dialog
        open={!!operation}
        onClose={() => setOperation(null)}
        fullWidth
        maxWidth="md"
      >
        <DialogTitle>
          {operation?.kind} · {date(operation?.created_at)}
        </DialogTitle>
        <DialogContent>
          <DataTable
            heads={["Нода", "Статус", "Ошибка"]}
            empty={!targets.length}
          >
            {targets.map((t) => (
              <TableRow key={t.node_id}>
                <TableCell>{t.name}</TableCell>
                <TableCell>
                  <Status value={t.status} />
                </TableCell>
                <TableCell>{t.error || "—"}</TableCell>
              </TableRow>
            ))}
          </DataTable>
        </DialogContent>
        <DialogActions>
          <Pagination {...targetPages.controls} />
          <Button onClick={() => setOperation(null)}>Закрыть</Button>
        </DialogActions>
      </Dialog>
      <Dialog
        open={!!recoveryToken}
        onClose={() => setRecoveryToken("")}
        fullWidth
      >
        <DialogTitle>Восстановление сертификата ноды</DialogTitle>
        <DialogContent>
          <Alert severity="info" sx={{ mb: 2 }}>
            Одно использование, 10 минут. Передайте токен на существующую ноду
            через HEIMDALL_RECOVERY_TOKEN и перезапустите агент. Локальные
            учётные записи сохраняются.
          </Alert>
          <TextField
            value={recoveryToken}
            multiline
            fullWidth
            InputProps={{ readOnly: true }}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRecoveryToken("")}>Закрыть</Button>
        </DialogActions>
      </Dialog>
      <Snackbar open={!!actionError} onClose={() => setActionError("")}>
        <Alert severity="error" onClose={() => setActionError("")}>
          {actionError}
        </Alert>
      </Snackbar>
      <Snackbar
        open={!!notice}
        message={notice}
        autoHideDuration={6000}
        onClose={() => setNotice("")}
      />
    </>
  );
  function nodeTable(nodes: Node[], actions: boolean) {
    return (
      <DataTable
        heads={["Нода", "Состояние", "ОС", ...(actions ? [""] : [])]}
        empty={!nodes.length}
      >
        {nodes.map((n) => (
          <TableRow key={n.id}>
            <TableCell>
              <Button
                sx={{ p: 0, textTransform: "none", fontWeight: 650 }}
                onClick={() => setNodeDetail(n)}
              >
                {n.name}
              </Button>
              <Typography variant="body2">
                {n.hostname || ""} {n.addresses?.join(", ")}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                {n.group_name}
              </Typography>
            </TableCell>
            <TableCell>
              <NodeHealth node={n} />
              {n.error && (
                <Typography color="error" fontSize={12} maxWidth={260}>
                  {n.error}
                </Typography>
              )}
            </TableCell>
            <TableCell>{n.platform || "—"}</TableCell>
            {actions && (
              <TableCell>
                {can(me!, "nodes.manage", n.group_id) && (
                  <Button
                    disabled={n.disabled}
                    onClick={() =>
                      void act(async () => {
                        const result = await api<{ token: string }>(
                          "/nodes/" + n.id + "/recovery-token",
                          "POST",
                          {},
                        );
                        setRecoveryToken(result.token);
                      })
                    }
                  >
                    Сертификат
                  </Button>
                )}
                {can(me!, "nodes.manage", n.group_id) && (
                  <Button
                    title="Отключение от CP сохраняет локальные УЗ и доступ. Для отзыва блокируйте пользователя."
                    color={n.disabled ? "primary" : "error"}
                    onClick={() =>
                      void act(() =>
                        api("/nodes/" + n.id, "PUT", {
                          group_id: n.group_id,
                          disabled: !n.disabled,
                        }),
                      )
                    }
                  >
                    {n.disabled ? "Включить" : "Отключить"}
                  </Button>
                )}
              </TableCell>
            )}
          </TableRow>
        ))}
      </DataTable>
    );
  }
}
