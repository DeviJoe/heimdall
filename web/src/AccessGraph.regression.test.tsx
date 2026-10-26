import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test, vi } from "vitest";
import { AccessGraph, type Connection } from "./AccessGraph";
import { AccessNavigation } from "./AccessNavigation";
import { AccessAssignments } from "./AccessAssignments";
import { administrator } from "./test/fixtures";

const connection: Connection = {
  id: "unix:binding",
  subject_id: "engineers",
  subject_name: "Engineers",
  subject_kind: "unix_group",
  group_id: "production",
  group_name: "Production",
  ancestors: ["production"],
  role: {
    id: "ssh",
    name: "SSH Engineer",
    permissions: ["users.manage"],
    linux_access: true,
    allow_ssh_keys: true,
    sudo: [],
  },
};

test("graph uses server pagination and reveals native grants without inventing Heimdall permissions", async () => {
  const fetcher = vi.fn(async (path: string) => {
    const second = path.includes("after=unix%3Abinding");
    return new Response(
      JSON.stringify({
        connections: second ? [] : [connection],
        recommendations: [],
      }),
      { headers: second ? {} : { "X-Heimdall-Next-Cursor": "unix:binding" } },
    );
  });
  vi.stubGlobal("fetch", fetcher);
  render(<AccessGraph />);
  await userEvent.click(
    await screen.findByRole("button", { name: "UNIX-группа: Engineers" }),
  );
  expect(
    screen.getByText("Engineers → SSH Engineer → Production"),
  ).toBeInTheDocument();
  expect(screen.getByText("SSH-ключи")).toBeInTheDocument();
  expect(screen.queryByText("users.manage")).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Далее" }));
  await screen.findByText("Назначений по этим фильтрам нет.");
  await waitFor(() =>
    expect(
      fetcher.mock.calls.some(([path]) =>
        path.includes("after=unix%3Abinding"),
      ),
    ).toBe(true),
  );
  expect(fetcher.mock.calls.every(([path]) => path.includes("limit=25"))).toBe(
    true,
  );
});

test("graph opens in a separate tab only with all catalog read permissions", () => {
  const view = render(<AccessNavigation me={administrator} page="roles" />);
  const link = screen.getByRole("tab", { name: "Граф доступов" });
  expect(link).toHaveAttribute("href", "/?page=access-graph");
  expect(link).toHaveAttribute("target", "_blank");
  const ordinary = {
    ...administrator,
    principal: { ...administrator.principal, bindings: [] },
  };
  view.rerender(<AccessNavigation me={ordinary} page="roles" />);
  expect(
    screen.queryByRole("tab", { name: "Граф доступов" }),
  ).not.toBeInTheDocument();
});
test("assignment dialog requests native roles and cancellation leaves access unchanged", async () => {
  const fetcher = vi.fn(async (path: string, init?: RequestInit) => {
    expect(init?.method || "GET").toBe("GET");
    return new Response(
      JSON.stringify(
        path.includes("/roles?status=unix")
          ? [{ id: "ssh", name: "SSH Engineer" }]
          : [],
      ),
    );
  });
  vi.stubGlobal("fetch", fetcher);
  render(
    <AccessAssignments
      me={administrator}
      act={async (fn) => {
        await fn();
      }}
    />,
  );
  await userEvent.click(
    screen.getByRole("button", { name: "Назначить доступ" }),
  );
  expect(
    screen.getByRole("combobox", { name: "1. UNIX-группа пользователей" }),
  ).toBeInTheDocument();
  await userEvent.click(
    screen.getByRole("combobox", { name: "2. Роль входа / sudo" }),
  );
  await userEvent.click(
    await screen.findByRole("option", { name: "SSH Engineer" }),
  );
  expect(screen.getByRole("button", { name: /^Назначить$/ })).toBeDisabled();
  await userEvent.click(screen.getByRole("button", { name: "Отмена" }));
  await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  expect(
    fetcher.mock.calls.some(([path]) => path.includes("/roles?status=unix")),
  ).toBe(true);
});
