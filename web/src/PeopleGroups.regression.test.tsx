import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test, vi } from "vitest";
import { PeopleGroups } from "./PeopleGroups";
import { AccessConfirmation } from "./AccessConfirmation";
import { administrator } from "./test/fixtures";
test("removing one visible member sends an incremental change without overwriting 20,000 members", async () => {
  const requests: { path: string; body: unknown }[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path: string, options?: RequestInit) => {
      if (options?.method === "POST") {
        requests.push({ path, body: JSON.parse(String(options.body)) });
        return new Response("{}");
      }
      const items = path.includes("/bindings")
        ? []
        : path.includes("/users?")
          ? [{ ...administrator.user, id: "visible", login: "visible" }]
          : [
              {
                id: "group",
                name: "Engineers",
                mfa_policy: "none",
                purpose: "general",
                member_count: 20000,
                totp_count: 0,
                passkey_count: 0,
                missing_factors: 0,
              },
            ];
      return new Response(JSON.stringify(items));
    }),
  );
  render(
    <AccessConfirmation>
      <PeopleGroups
        me={administrator}
        roles={[]}
        groups={[]}
        act={async (fn) => {
          await fn();
        }}
      />
    </AccessConfirmation>,
  );
  await userEvent.click(
    await screen.findByRole("button", { name: /Engineers/ }),
  );
  await userEvent.click(
    await screen.findByRole("checkbox", { name: "Выбрать visible" }),
  );
  await userEvent.click(
    screen.getByRole("button", { name: "Убрать из группы" }),
  );
  expect(requests).toHaveLength(0);
  await userEvent.click(
    screen.getByRole("button", { name: "Подтвердить изменение" }),
  );
  await waitFor(() =>
    expect(requests).toContainEqual({
      path: "/api/v1/user-groups/group/members/remove",
      body: { users: ["visible"] },
    }),
  );
  expect(
    requests.every((r) => !String(JSON.stringify(r.body)).includes("members")),
  ).toBe(true);
});
