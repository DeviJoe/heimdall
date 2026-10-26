import { render, screen } from "@testing-library/react";
import { expect, test } from "vitest";
import { SafeMarkdown } from "./Announcements";
test("administrator Markdown cannot inject scripts, unsafe URLs or tracking images", () => {
  const { container } = render(
    <SafeMarkdown>
      {
        "**Restart**\n\n<script>alert(1)</script>\n\n[unsafe](javascript:alert%281%29)\n\n![tracking](https://example.org/track.png)\n\n[safe](https://example.org/docs)"
      }
    </SafeMarkdown>,
  );
  expect(screen.getByText("Restart").tagName).toBe("STRONG");
  expect(container.querySelector("script")).toBeNull();
  expect(container.querySelector("img")).toBeNull();
  expect(screen.getByText("unsafe")).not.toHaveAttribute(
    "href",
    "javascript:alert%281%29",
  );
  expect(screen.getByRole("link", { name: "safe" })).toHaveAttribute(
    "rel",
    "noopener noreferrer",
  );
});
test("documentation tables and task lists render while HTML remains disabled", () => {
  const { container } = render(
    <SafeMarkdown>
      {
        '| Раздел | Назначение |\n| --- | --- |\n| UNIX-каталог | Группы ОС |\n\n- [x] Назначено\n\n<iframe src="https://example.org"></iframe>'
      }
    </SafeMarkdown>,
  );
  expect(screen.getByRole("table")).toBeInTheDocument();
  expect(screen.getByRole("cell", { name: "Группы ОС" })).toBeInTheDocument();
  expect(screen.getByRole("checkbox")).toBeDisabled();
  expect(container.querySelector("iframe")).toBeNull();
});
