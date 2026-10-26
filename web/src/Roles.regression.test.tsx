import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test, vi } from "vitest";
import { Roles } from "./Roles";
import { administrator } from "./test/fixtures";

test("native role creation shows only login methods and native sudo; switching purpose and cancelling does not change access", async () => {
  const act = vi.fn();
  render(<Roles me={administrator} roles={[]} groups={[]} users={[]} act={act} kind="unix" />);
  await userEvent.click(screen.getByRole("button", { name: "Создать роль" }));
  const dialog = within(screen.getByRole("dialog"));
  expect(dialog.queryByRole("tab", { name: "Права Heimdall" })).not.toBeInTheDocument();
  expect(dialog.getByRole("checkbox", { name: "Разрешить вход по SSH-ключам" })).not.toBeChecked();
  expect(dialog.getByRole("checkbox", { name: "Разрешить вход по UNIX-паролю" })).not.toBeChecked();
  await userEvent.click(dialog.getByRole("checkbox", { name: "Разрешить вход по SSH-ключам" }));
  await userEvent.click(dialog.getByRole("combobox", { name: "Назначение роли" }));
  await userEvent.click(screen.getByRole("option", { name: "Управление Heimdall" }));
  expect(dialog.getByRole("tab", { name: "Права Heimdall" })).toBeInTheDocument();
  expect(dialog.queryByRole("tab", { name: "sudoers" })).not.toBeInTheDocument();
  await userEvent.click(dialog.getByRole("combobox", { name: "Назначение роли" }));
  await userEvent.click(screen.getByRole("option", { name: "Совмещённая роль" }));
  expect(dialog.getByRole("tab", { name: "Права Heimdall" })).toBeInTheDocument();
  expect(dialog.getByRole("tab", { name: "sudoers" })).toBeInTheDocument();
  expect(dialog.getByRole("checkbox", { name: "Разрешить вход по SSH-ключам" })).not.toBeChecked();
  await userEvent.click(dialog.getByRole("button", { name: "Отмена" }));
  await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  expect(act).not.toHaveBeenCalled();
});
