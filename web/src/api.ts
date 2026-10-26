import { accessAction, type AccessAction } from "./accessActions";

type ConfirmationHandler = (action: AccessAction) => Promise<boolean>;
let confirmation: ConfirmationHandler | undefined;
export function installAccessConfirmation(handler: ConfirmationHandler) {
  confirmation = handler;
  return () => {
    if (confirmation === handler) confirmation = undefined;
  };
}
export class ActionCancelledError extends Error {
  constructor() {
    super("Действие отменено");
  }
}
export class APIError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}
async function request(path: string, options: RequestInit = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await fetch("/api/v1" + path, {
      ...options,
      credentials: "same-origin",
      signal: controller.signal,
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok)
      throw new APIError(
        response.status,
        data?.error || `HTTP ${response.status}`,
      );
    return { response, data };
  } catch (error) {
    if (controller.signal.aborted)
      throw new APIError(
        408,
        "Сервер не ответил за 15 секунд. Повторите запрос.",
      );
    if (error instanceof APIError) throw error;
    throw new APIError(
      0,
      "Не удалось связаться с сервером. Проверьте подключение.",
    );
  } finally {
    clearTimeout(timer);
  }
}
export async function api<T>(
  path: string,
  method = "GET",
  body?: unknown,
  options: { confirmed?: boolean } = {},
): Promise<T> {
  method = method.toUpperCase();
  const serialized = body === undefined ? undefined : JSON.stringify(body);
  const action = accessAction(
    path,
    method,
    serialized ? JSON.parse(serialized) : undefined,
  );
  // confirmed is only for an existing explicit consequence-confirmation dialog.
  // Server-side RBAC and last-administrator protections remain authoritative.
  if (action && !options.confirmed) {
    if (!confirmation)
      throw new Error(
        "Подтверждение действия недоступно. Откройте страницу заново.",
      );
    if (!(await confirmation(action))) throw new ActionCancelledError();
  }
  const { data } = await request(path, {
    method,
    headers: { "Content-Type": "application/json", "X-Heimdall-CSRF": "1" },
    body: serialized,
  });
  return data as T;
}
export function canAny(me: import("./types").Me, permission: string) {
  return (
    !me.principal.restricted &&
    (me.principal.bindings ?? []).some(
      (b) =>
        (b.role.permissions ?? []).includes("*") ||
        (b.role.permissions ?? []).includes(permission),
    )
  );
}
export function can(me: import("./types").Me, permission: string, group = "*") {
  return (
    !me.principal.restricted &&
    (me.principal.bindings ?? []).some(
      (b) =>
        (b.group_id === "*" || b.group_id === group) &&
        ((b.role.permissions ?? []).includes("*") ||
          (b.role.permissions ?? []).includes(permission)),
    )
  );
}
export function date(value: string | null | undefined) {
  return value ? new Date(value).toLocaleString("ru-RU") : "—";
}
export function age(value: string | null | undefined) {
  if (!value) return "не получен";
  const seconds = Math.max(
    0,
    Math.floor((Date.now() - new Date(value).getTime()) / 1000),
  );
  return seconds < 60
    ? `${seconds} сек. назад`
    : seconds < 3600
      ? `${Math.floor(seconds / 60)} мин. назад`
      : `${Math.floor(seconds / 3600)} ч. назад`;
}

export async function page<T>(path: string) {
  const { response, data } = await request(path);
  return {
    items: data as T[],
    next: response.headers.get("X-Heimdall-Next-Cursor") || "",
  };
}

export async function apiWithCursor<T>(path: string) {
  const { response, data } = await request(path);
  return {
    data: data as T,
    next: response.headers.get("X-Heimdall-Next-Cursor") || "",
  };
}
