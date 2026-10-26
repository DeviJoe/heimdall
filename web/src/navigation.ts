export const pages = [
  "overview",
  "users",
  "people-groups",
  "nodes",
  "roles",
  "unix",
  "sync",
  "account",
  "tokens",
  "audit",
  "settings",
  "docs",
  "join-tokens",
  "access-assignments",
  "access-graph",
] as const;
export function currentPage() {
  const page = new URLSearchParams(window.location.search).get("page");
  return pages.includes(page as (typeof pages)[number]) ? page! : "overview";
}
export function pageURL(page: string) {
  return "/?page=" + encodeURIComponent(page);
}
