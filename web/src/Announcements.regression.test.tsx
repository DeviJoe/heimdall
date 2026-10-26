import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test, vi } from "vitest";
import { Announcements } from "./Announcements";
import { AccessConfirmation } from "./AccessConfirmation";
import { ActionCancelledError } from "./api";
import { administrator } from "./test/fixtures";

test("announcement deletion requires confirmation and refreshes the overview and manager", async () => {
  let items = [
    {
      id: "maintenance",
      title: "Maintenance",
      markdown: "Restart tonight",
      severity: "info",
      enabled: true,
      version: 3,
    },
    {
      id: "reference",
      title: "Reference",
      markdown: "Team documentation",
      severity: "info",
      enabled: true,
      version: 1,
    },
  ];
  const fetcher = vi.fn(async (path: string, init?: RequestInit) => {
    if (init?.method === "DELETE") {
      expect(path).toBe("/api/v1/announcements/maintenance?version=3");
      items = items.filter((item) => item.id !== "maintenance");
      return new Response(JSON.stringify({ operation_id: "deleted" }));
    }
    return new Response(JSON.stringify(items));
  });
  vi.stubGlobal("fetch", fetcher);
  render(
    <AccessConfirmation>
      <Announcements
        me={administrator}
        updated={0}
        act={async (fn) => {
          try {
            await fn();
          } catch (error) {
            if (!(error instanceof ActionCancelledError)) throw error;
          }
        }}
      />
    </AccessConfirmation>,
  );
  await screen.findByText("Maintenance");
  await userEvent.click(
    screen.getByRole("button", { name: "Сообщения администратора" }),
  );
  const button = await screen.findByRole("button", {
    name: "Удалить сообщение «Maintenance»",
  });
  await userEvent.click(button);
  expect(fetcher.mock.calls.some(([, init]) => init?.method === "DELETE")).toBe(
    false,
  );
  await userEvent.click(screen.getByRole("button", { name: "Отмена" }));
  expect(items).toHaveLength(2);
  await userEvent.click(
    await screen.findByRole("button", { name: "Удалить сообщение «Maintenance»" }),
  );
  await userEvent.click(
    screen.getByRole("button", { name: "Удалить сообщение" }),
  );
  await waitFor(() =>
    expect(
      screen.queryByRole("button", { name: "Удалить сообщение «Maintenance»" }),
    ).not.toBeInTheDocument(),
  );
  expect(
    screen.queryByText("Maintenance", { exact: true }),
  ).not.toBeInTheDocument();
  expect(
    await screen.findByRole("button", { name: "Удалить сообщение «Reference»" }),
  ).toBeInTheDocument();
  expect(items).toHaveLength(1);
});

test("ordinary users can read messages without announcement management controls", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => new Response(JSON.stringify([]))),
  );
  const me = {
    ...administrator,
    principal: { ...administrator.principal, bindings: [] },
  };
  render(
    <Announcements
      me={me}
      updated={0}
      act={async (fn) => {
        await fn();
      }}
    />,
  );
  expect(
    screen.queryByRole("button", { name: "Сообщения администратора" }),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByRole("button", { name: /Удалить/ }),
  ).not.toBeInTheDocument();
});
