import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test, vi } from "vitest";
import { Roles } from "./Roles";
import type { Role } from "./types";
import { administrator } from "./test/fixtures";
test("legacy null sudo and permissions render and remain editable", async () => {
  render(
    <Roles
      me={administrator}
      roles={[
        {
          id: "legacy",
          name: "Legacy",
          permissions: null,
          linux_access: true,
          sudo: null,
        } as unknown as Role,
      ]}
      groups={[]}
      users={[]}
      act={vi.fn()}
    />,
  );
  expect(screen.getByText("Legacy")).toBeVisible();
  await userEvent.click(screen.getByRole("button", { name: "Настроить" }));
  expect(screen.getByRole("dialog")).toBeVisible();
  await userEvent.click(screen.getByRole("tab", { name: "sudoers" }));
  expect(
    screen.getByLabelText("User_Spec после имени UNIX-пользователя"),
  ).toHaveValue("");
});
