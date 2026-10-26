import { render, screen } from "@testing-library/react";
import { expect, test } from "vitest";
import { NodeHealth, nodeHealth } from "./NodeHealth";
test("one health indicator distinguishes sync failure from offline", () => {
  expect(
    nodeHealth({
      health: "healthy",
      disabled: false,
      connectivity: "online",
      status: "in_sync",
    }),
  ).toBe("healthy");
  expect(
    nodeHealth({
      health: "warning",
      disabled: false,
      connectivity: "online",
      status: "failed",
    }),
  ).toBe("warning");
  render(
    <NodeHealth
      node={{
        health: "offline",
        disabled: false,
        connectivity: "offline",
        status: "in_sync",
      }}
    />,
  );
  expect(screen.getByText("Offline")).toBeVisible();
});
