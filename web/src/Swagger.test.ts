// @vitest-environment node
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import { URL } from "node:url";
import { expect, test, vi } from "vitest";

type Request = {
  method?: string;
  url?: string;
  headers?: Record<string, string>;
  credentials?: string;
};
function swaggerOptions(confirm: (message: string) => boolean) {
  const source = readFileSync(
    new URL("../../internal/transport/httpapi/openapi.go", import.meta.url),
    "utf8",
  );
  const script = source.match(
    /<script>(SwaggerUIBundle\([\s\S]+?)<\/script>/,
  )?.[1];
  if (!script) throw new Error("Swagger bootstrap script is missing");
  let options!: {
    requestInterceptor: (request: Request) => Request;
    persistAuthorization: boolean;
  };
  runInNewContext(script, {
    SwaggerUIBundle: (value: typeof options) => {
      options = value;
    },
    confirm,
  });
  return options;
}
test("Swagger can fetch its definition without a method and without a confirmation prompt", () => {
  const confirm = vi.fn(() => true),
    options = swaggerOptions(confirm);
  const request = options.requestInterceptor({ url: "/api/v1/openapi.json" });
  expect(request.credentials).toBe("same-origin");
  expect(confirm).not.toHaveBeenCalled();
  expect(options.persistAuthorization).toBe(false);
});
test("Swagger cancellation prevents a write; confirmed writes carry CSRF and preserve headers", () => {
  const confirm = vi.fn(() => false),
    options = swaggerOptions(confirm);
  expect(() =>
    options.requestInterceptor({ method: "DELETE", url: "/api/v1/roles/role" }),
  ).toThrow("Действие отменено");
  confirm.mockReturnValue(true);
  const request = options.requestInterceptor({
    method: "post",
    url: "/api/v1/bindings",
    headers: { Authorization: "Bearer fixture" },
  });
  expect(request.headers).toEqual({
    Authorization: "Bearer fixture",
    "X-Heimdall-CSRF": "1",
  });
  expect(request.credentials).toBe("same-origin");
  expect(confirm).toHaveBeenCalledTimes(2);
});
