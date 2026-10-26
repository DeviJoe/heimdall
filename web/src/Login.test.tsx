import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test, vi } from "vitest";
import { Login } from "./Login";
test("invitation submits its token and shows server failure visibly", async () => {
  history.replaceState({}, "", "/invite#invitation-secret");
  const fetchMock = vi
    .fn()
    .mockResolvedValueOnce(new Response("[]"))
    .mockResolvedValueOnce(
      new Response(JSON.stringify({ error: "Приглашение истекло" }), {
        status: 400,
      }),
    );
  vi.stubGlobal("fetch", fetchMock);
  render(<Login onLogin={vi.fn()} />);
  await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
  await userEvent.type(
    screen.getByLabelText(/пароль/i),
    "Valid-password-for-test",
  );
  await userEvent.click(screen.getByRole("button", { name: "Создать пароль" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "Приглашение истекло",
  );
  expect(JSON.parse(fetchMock.mock.calls[1][1].body)).toEqual({
    token: "invitation-secret",
    password: "Valid-password-for-test",
  });
  expect(screen.queryByText("Linux access")).not.toBeInTheDocument();
});
test("ordinary login API failure stays on the form", async () => {
  vi.stubGlobal(
    "fetch",
    vi
      .fn()
      .mockResolvedValueOnce(new Response("[]"))
      .mockResolvedValueOnce(
        new Response('{"error":"Неверный пароль"}', { status: 401 }),
      ),
  );
  render(<Login onLogin={vi.fn()} />);
  await userEvent.type(screen.getByLabelText(/пароль/i), "bad-password");
  await userEvent.click(screen.getByRole("button", { name: "Войти" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Неверный пароль");
});
