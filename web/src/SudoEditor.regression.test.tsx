import { useState } from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test } from "vitest";
import { SudoEditor } from "./SudoEditor";
test("tabs preserve manual syntax and delete the original row even after blank lines", async () => {
  function Editor() {
    const [value, setValue] = useState(
      '\nALL=(root) NOPASSWD: /usr/bin/id ""\nALL=(ALL:ALL) NOEXEC: /usr/bin/less *',
    );
    return <SudoEditor value={value} onChange={setValue} />;
  }
  render(<Editor />);
  await userEvent.click(screen.getByRole("tab", { name: "Конструктор" }));
  await userEvent.click(
    screen.getAllByRole("button", { name: "Удалить правило" })[0],
  );
  await userEvent.click(screen.getByRole("tab", { name: "Текст" }));
  expect(
    screen.getByLabelText("User_Spec после имени UNIX-пользователя"),
  ).toHaveValue("\nALL=(ALL:ALL) NOEXEC: /usr/bin/less *");
});
