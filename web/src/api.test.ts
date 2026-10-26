import { afterEach, expect, it, vi } from "vitest";
import { api, APIError, page } from "./api";
afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});
it("keeps HTTP errors visible when the API returns null or non-JSON", async () => {
  for (const body of ["null", "upstream unavailable"]) {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response(body, { status: 503 })),
    );
    await expect(api("/me")).rejects.toMatchObject({
      status: 503,
      message: "HTTP 503",
    });
    await expect(page("/nodes")).rejects.toBeInstanceOf(APIError);
  }
});
it("retains the server error and pagination cursor", async () => {
  vi.stubGlobal(
    "fetch",
    vi
      .fn()
      .mockResolvedValue(
        new Response('{"error":"Доступ запрещён"}', { status: 403 }),
      ),
  );
  await expect(api("/roles")).rejects.toThrow("Доступ запрещён");
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue(
      new Response("[]", {
        status: 200,
        headers: { "X-Heimdall-Next-Cursor": "next" },
      }),
    ),
  );
  await expect(page("/nodes")).resolves.toEqual({ items: [], next: "next" });
});

it("bounds stalled requests and reports a visible timeout", async () => {
  vi.useFakeTimers();
  vi.stubGlobal(
    "fetch",
    vi.fn(
      (_url, options) =>
        new Promise((_resolve, reject) => {
          options.signal.addEventListener("abort", () =>
            reject(new DOMException("Aborted", "AbortError")),
          );
        }),
    ),
  );
  const result = expect(api("/me")).rejects.toMatchObject({
    status: 408,
    message: "Сервер не ответил за 15 секунд. Повторите запрос.",
  });
  await vi.advanceTimersByTimeAsync(15000);
  await result;
});

it("cancelled access changes never reach the API", async () => {
  const { installAccessConfirmation, ActionCancelledError } =
    await import("./api");
  const fetcher = vi.fn();
  vi.stubGlobal("fetch", fetcher);
  const uninstall = installAccessConfirmation(async () => false);
  try {
    await expect(api("/keys/k", "DELETE")).rejects.toBeInstanceOf(
      ActionCancelledError,
    );
    expect(fetcher).not.toHaveBeenCalled();
  } finally {
    uninstall();
  }
});
it("sends the reviewed immutable request only after confirmation", async () => {
  const { installAccessConfirmation } = await import("./api");
  const fetcher = vi.fn(async () => new Response("{}"));
  vi.stubGlobal("fetch", fetcher);
  let approve: ((value: boolean) => void) | undefined;
  const uninstall = installAccessConfirmation(
    () =>
      new Promise((resolve) => {
        approve = resolve;
      }),
  );
  try {
    const body = { policy: "totp" };
    const operation = api("/me/factor-policy", "PUT", body);
    expect(fetcher).not.toHaveBeenCalled();
    body.policy = "none";
    approve!(true);
    await operation;
    expect(fetcher).toHaveBeenCalledWith(
      "/api/v1/me/factor-policy",
      expect.objectContaining({ body: '{"policy":"totp"}' }),
    );
  } finally {
    uninstall();
  }
});
