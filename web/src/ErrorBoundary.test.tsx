import { render, screen } from "@testing-library/react";
import { expect, test, vi } from "vitest";
import { ErrorBoundary } from "./ErrorBoundary";
test("render failure displays a recoverable error instead of blank screen", () => {
  vi.spyOn(console, "error").mockImplementation(() => {});
  function Broken(): never {
    throw new Error("test failure");
  }
  render(
    <ErrorBoundary>
      <Broken />
    </ErrorBoundary>,
  );
  expect(screen.getByRole("alert")).toHaveTextContent("test failure");
  expect(screen.getByRole("button", { name: "Перезагрузить" })).toBeVisible();
});
