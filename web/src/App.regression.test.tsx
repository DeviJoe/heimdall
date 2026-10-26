import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test, vi } from "vitest";
import { App } from "./App";
import { administrator } from "./test/fixtures";
function mockAPI() {
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async (path: string) =>
        new Response(
          JSON.stringify(
            path.endsWith("/me")
              ? administrator
              : path.endsWith("/summary")
                ? { nodes: 0, healthy: 0, pending: 0, incidents: 0 }
                : [],
          ),
        ),
    ),
  );
}
test("invitation opens while another user is already logged in", async () => {
  mockAPI();
  history.replaceState({}, "", "/invite#new-user-token");
  render(<App />);
  expect(await screen.findByText("Первый вход")).toBeVisible();
  expect(screen.getByRole("button", { name: "Создать пароль" })).toBeVisible();
});
test("navigation preserves page in URL and survives reload", async () => {
  mockAPI();
  history.replaceState({}, "", "/?page=roles");
  const rendered = render(<App />);
  expect(await screen.findByRole("heading", { name: "Роли" })).toBeVisible();
  await userEvent.click(
    screen.getAllByRole("link", { name: "Пользователи" })[0],
  );
  await waitFor(() => expect(location.search).toBe("?page=users"));
  rendered.unmount();
  render(<App />);
  expect(
    await screen.findByRole("heading", { name: "Пользователи" }),
  ).toBeVisible();
});
test("mutation failure remains visible above a modal dialog", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path: string, options?: RequestInit) => {
      if (path.endsWith("/roles") && options?.method === "POST")
        return new Response('{"error":"Роль уже существует"}', { status: 409 });
      return new Response(
        JSON.stringify(
          path.endsWith("/me")
            ? administrator
            : path.endsWith("/summary")
              ? { nodes: 0, healthy: 0, pending: 0, incidents: 0 }
              : [],
        ),
      );
    }),
  );
  history.replaceState({}, "", "/?page=roles");
  render(<App />);
  await userEvent.click(
    await screen.findByRole("button", { name: "Создать роль" }),
  );
  await userEvent.type(screen.getByLabelText("Название"), "duplicate");
  await userEvent.click(screen.getByRole("button", { name: "Сохранить" }));
  expect(await screen.findByText("Роль уже существует")).toBeVisible();
  expect(screen.getByRole("dialog")).toBeVisible();
});

test("ordinary user's overview is an access directory and makes no monitoring requests", async () => {
  const nativeUser = {
    ...administrator,
    principal: {
      ...administrator.principal,
      bindings: [
        {
          ...administrator.principal.bindings[0],
          role: {
            ...administrator.principal.bindings[0].role,
            permissions: [],
            linux_access: true,
          },
        },
      ],
    },
  };
  const fetcher = vi.fn(
    async (path: string) =>
      new Response(
        JSON.stringify(
          path.endsWith("/me")
            ? nativeUser
            : path.includes("/me/nodes?")
              ? [
                  {
                    id: "n",
                    name: "linux-web",
                    hostname: "web.internal",
                    addresses: ["10.0.0.1"],
                    platform: "linux",
                    group_name: "Production",
                    host: "localhost",
                    port: 22223,
                    login: "ivanov",
                    access_status: "applied",
                    roles: [],
                  },
                ]
              : [],
        ),
      ),
  );
  vi.stubGlobal("fetch", fetcher);
  history.replaceState({}, "", "/?page=sync");
  render(<App />);
  expect(
    await screen.findByRole("heading", { name: "Доступные ноды" }),
  ).toBeVisible();
  expect(await screen.findByText("linux-web")).toBeVisible();
  expect(
    screen.queryByRole("link", { name: "Синхронизация" }),
  ).not.toBeInTheDocument();
  expect(screen.queryByText("Последние инциденты")).not.toBeInTheDocument();
  expect(screen.queryByText("Control plane")).not.toBeInTheDocument();
  expect(
    screen.queryByRole("button", { name: "Обновить" }),
  ).not.toBeInTheDocument();
  expect(
    fetcher.mock.calls.every(
      ([path]) => !/\/(summary|incidents|operations|groups)(\?|$)/.test(path),
    ),
  ).toBe(true);
});
