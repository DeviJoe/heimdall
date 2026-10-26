import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test, vi } from "vitest";
import { Account } from "./Account";
import { AccessConfirmation } from "./AccessConfirmation";
import { administrator } from "./test/fixtures";

test("required TOTP enrollment is available after a passkey in a restricted session", async () => {
  const user = {
    ...administrator.user,
    id: "engineer",
    login: "engineer",
    kind: "human" as const,
    mfa_enabled: true,
    totp_enabled: false,
    passkey_count: 1,
  };
  const me = {
    ...administrator,
    user,
    principal: {
      ...administrator.principal,
      user_id: user.id,
      restricted: true,
      bindings: [],
    },
    factor_state: { required: ["totp"], totp: false, passkey: true },
  };
  const requests: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path: string) => {
      requests.push(path);
      if (path.endsWith("/factors"))
        return new Response(
          JSON.stringify({
            totp_enabled: false,
            required: ["totp"],
            administrator_required: ["totp"],
            personal_policy: "none",
            can_remove_totp: false,
            can_remove_passkey: false,
            passkeys: [
              {
                id: "existing",
                name: "Existing passkey",
                created_at: null,
                last_used: null,
              },
            ],
          }),
        );
      if (path.endsWith("/totp/begin"))
        return new Response(
          JSON.stringify({
            secret: "TESTONLY",
            uri: "otpauth://totp/Heimdall:engineer?secret=TESTONLY",
          }),
        );
      if (path.endsWith("/totp/finish"))
        return new Response(
          JSON.stringify({ recovery_codes: ["fixture-recovery-code"] }),
        );
      throw new Error("Unexpected request: " + path);
    }),
  );
  render(
    <AccessConfirmation>
      <Account
        me={me}
        user={user}
        groups={[]}
        roles={[]}
        act={async (fn) => {
          await fn();
        }}
      />
    </AccessConfirmation>,
  );
  expect(await screen.findByLabelText("Имя passkey")).toHaveValue(
    "Existing passkey",
  );
  expect(screen.getByText("TOTP не настроен")).toBeInTheDocument();
  expect(screen.getByText("Passkey: 1")).toBeInTheDocument();
  expect(
    screen.queryByRole("img", { name: "QR-код для регистрации TOTP" }),
  ).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Настроить TOTP" }));
  await waitFor(() =>
    expect(screen.getByLabelText("Секрет TOTP")).toHaveValue("TESTONLY"),
  );
  expect(
    screen.getByRole("textbox", { name: "Код из приложения" }),
  ).toBeEnabled();
  expect(screen.getByRole("button", { name: "Подтвердить" })).toBeEnabled();
  expect(
    screen.getByRole("img", { name: "QR-код для регистрации TOTP" }),
  ).toBeVisible();
  expect(screen.getByLabelText("Имя passkey")).toHaveValue("Existing passkey");
  expect(requests).toContain("/api/v1/me/totp/begin");
  expect(requests.every((path) => !path.includes("/keys"))).toBe(true);
  await userEvent.type(
    screen.getByRole("textbox", { name: "Код из приложения" }),
    "123456",
  );
  await userEvent.click(screen.getByRole("button", { name: "Подтвердить" }));
  expect(requests).not.toContain("/api/v1/me/totp/finish");
  await userEvent.click(screen.getByRole("button", { name: "Включить TOTP" }));
  await waitFor(() =>
    expect(
      screen.queryByRole("img", { name: "QR-код для регистрации TOTP" }),
    ).not.toBeInTheDocument(),
  );
  expect(screen.queryByLabelText("Секрет TOTP")).not.toBeInTheDocument();
  expect(screen.getByLabelText("Имя passkey")).toHaveValue("Existing passkey");
});
