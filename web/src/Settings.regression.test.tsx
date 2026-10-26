import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test, vi } from "vitest";
import { Settings } from "./Settings";
import { AccessConfirmation } from "./AccessConfirmation";

test("certificate TTL defaults to ten years and confirmed changes show offline rollout without losing a draft on events", async () => {
  let settings = {
    version: 1, node_certificate_ttl_seconds: 315360000, certificate_policy_version: 1,
    certificates_total: 4, certificates_pending: 0, apply_timeout_seconds: 900,
    key_ttl_seconds: 86400, key_warn_seconds: 3600, require_sk: false,
    stalled_seconds: 45, offline_seconds: 45, revocation_alert_seconds: 20,
    swagger_enabled: true, mcp_enabled: true,
  };
  const fetcher = vi.fn(async (_path: string, init?: RequestInit) => {
    if (init?.method === "PUT") {
      settings = {...JSON.parse(String(init.body)), version: 2, certificate_policy_version: 2, certificates_pending: 1};
      return new Response(JSON.stringify({operation_id: "certificate-rollout"}));
    }
    return new Response(JSON.stringify(settings));
  });
  vi.stubGlobal("fetch", fetcher);
  const act = async (fn: () => Promise<unknown>) => { await fn(); };
  const view = render(<AccessConfirmation><Settings act={act} updated={0} /></AccessConfirmation>);
  const ttl = await screen.findByLabelText("Срок жизни сертификатов нод");
  expect(ttl).toHaveValue("3650d");
  await userEvent.clear(ttl); await userEvent.type(ttl, "365d");
  // SSE refreshes progress only; it must not replace an unsaved TTL draft.
  view.rerender(<AccessConfirmation><Settings act={act} updated={1} /></AccessConfirmation>);
  await waitFor(() => expect(fetcher.mock.calls.length).toBeGreaterThan(2));
  expect(ttl).toHaveValue("365d");
  await userEvent.click(screen.getByRole("button", {name:"Сохранить"}));
  expect(fetcher.mock.calls.some(([, init]) => init?.method === "PUT")).toBe(false);
  expect(within(screen.getByRole("dialog")).getByText(/offline-ноды обновятся после подключения/)).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", {name:"Подтвердить изменение"}));
  await screen.findByText(/Ожидают перевыпуска: 1/);
  expect(settings.node_certificate_ttl_seconds).toBe(365*86400);
  expect(settings.certificate_policy_version).toBe(2);
});
