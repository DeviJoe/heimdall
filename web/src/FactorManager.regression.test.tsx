import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test, vi } from "vitest";
import { FactorManager } from "./FactorManager";
import { AccessConfirmation } from "./AccessConfirmation";
import { administrator } from "./test/fixtures";

test("mandatory factors cannot be removed and personal requirements preserve the displayed floor", async () => {
  const user = { ...administrator.user, totp_enabled: true, passkey_count: 1 };
  const me = {
    ...administrator,
    user,
    principal: { ...administrator.principal, bindings: [] },
  };
  let personal = "both";
  const fetcher = vi.fn(async (_path: string, init?: RequestInit) => {
    if (init?.method === "PUT") {
      personal = JSON.parse(String(init.body)).policy;
      return new Response(JSON.stringify({ operation_id: "policy-change" }));
    }
    return new Response(
      JSON.stringify({
        passkeys: [
          {
            id: "hardware-key",
            name: "Hardware passkey",
            created_at: null,
            last_used: null,
          },
        ],
        totp_enabled: true,
        required: ["both"],
        administrator_required: ["both"],
        personal_policy: personal,
        can_remove_totp: false,
        can_remove_passkey: false,
      }),
    );
  });
  vi.stubGlobal("fetch", fetcher);
  render(
    <AccessConfirmation>
      <FactorManager
        me={me}
        user={user}
        act={async (fn) => {
          await fn();
        }}
      />
    </AccessConfirmation>,
  );
  expect(
    await screen.findByRole("button", { name: "Отвязать TOTP" }),
  ).toBeDisabled();
  expect(
    screen.getByRole("button", { name: "Удалить passkey" }),
  ).toBeDisabled();
  expect(
    screen.getByText("Последний обязательный Passkey"),
  ).toBeInTheDocument();
  expect(
    screen.getByText("Минимум администратора и групп: TOTP и passkey"),
  ).toBeInTheDocument();
  await userEvent.click(
    screen.getByRole("combobox", { name: "Мои дополнительные требования" }),
  );
  await userEvent.click(
    screen.getByRole("option", { name: "По политике администратора" }),
  );
  expect(
    screen.getByText("Итоговое требование: TOTP и passkey"),
  ).toBeInTheDocument();
  await userEvent.click(
    screen.getByRole("button", { name: "Сохранить мои требования" }),
  );
  expect(personal).toBe("both");
  await userEvent.click(
    screen.getByRole("button", { name: "Подтвердить изменение" }),
  );
  await waitFor(() =>
    expect(fetcher).toHaveBeenCalledWith(
      "/api/v1/me/factor-policy",
      expect.objectContaining({
        method: "PUT",
        body: JSON.stringify({ policy: "none" }),
      }),
    ),
  );
  expect(await screen.findByRole("button", { name: "Отвязать TOTP" })).toBeDisabled();
  expect(
    await screen.findByRole("button", { name: "Удалить passkey" }),
  ).toBeDisabled();
});

test("one of several required passkeys may be removed while the last one stays protected", async () => {
  const user = { ...administrator.user, passkey_count: 2 };
  const me = { ...administrator, user };
  let keys = ["first", "second"];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path: string, init?: RequestInit) => {
      if (init?.method === "DELETE") {
        keys = keys.filter((key) => !path.endsWith("/" + key));
        return new Response(JSON.stringify({ operation_id: "factor-removed" }));
      }
      return new Response(
        JSON.stringify({
          passkeys: keys.map((id) => ({
            id,
            name: id,
            created_at: null,
            last_used: null,
          })),
          totp_enabled: false,
          required: ["passkey"],
          administrator_required: ["passkey"],
          personal_policy: "none",
          can_remove_totp: true,
          can_remove_passkey: keys.length > 1,
        }),
      );
    }),
  );
  render(
    <AccessConfirmation>
      <FactorManager
        me={me}
        user={user}
        act={async (fn) => {
          await fn();
        }}
      />
    </AccessConfirmation>,
  );
  const buttons = await screen.findAllByRole("button", {
    name: "Удалить passkey",
  });
  expect(buttons[0]).toBeEnabled();
  await userEvent.click(buttons[0]);
  await userEvent.click(
    screen.getByRole("button", { name: "Отвязать фактор" }),
  );
  await waitFor(() =>
    expect(screen.getAllByLabelText("Имя passkey")).toHaveLength(1),
  );
  expect(
    await screen.findByRole("button", { name: "Удалить passkey" }),
  ).toBeDisabled();
  expect(keys).toEqual(["second"]);
});

test("mandatory TOTP can be replaced without allowing factor removal", async () => {
  const user = { ...administrator.user, totp_enabled: true };
  const rotate = vi.fn();
  const me = {
    ...administrator,
    user,
    principal: { ...administrator.principal, bindings: [] },
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            passkeys: [],
            totp_enabled: true,
            required: ["totp"],
            administrator_required: ["totp"],
            personal_policy: "none",
            can_remove_totp: false,
            can_remove_passkey: false,
          }),
        ),
    ),
  );
  render(
    <FactorManager
      me={me}
      user={user}
      onRotateTOTP={rotate}
      act={async (fn) => {
        await fn();
      }}
    />,
  );
  expect(
    await screen.findByRole("button", { name: "Отвязать TOTP" }),
  ).toBeDisabled();
  await userEvent.click(screen.getByRole("button", { name: "Заменить TOTP" }));
  expect(rotate).toHaveBeenCalledOnce();
});
