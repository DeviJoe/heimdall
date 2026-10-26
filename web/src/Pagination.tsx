import { useCallback, useEffect, useState } from "react";
import { Button, Stack, Typography } from "@mui/material";
import { page } from "./api";
export function Pagination({
  index,
  next,
  previous,
  advance,
}: {
  index: number;
  next: boolean;
  previous: () => void;
  advance: () => void;
}) {
  return (
    <Stack
      direction="row"
      gap={1}
      alignItems="center"
      justifyContent="flex-end"
      mt={2}
    >
      <Button disabled={!index} onClick={previous}>
        Назад
      </Button>
      <Typography variant="body2">Страница {index + 1}</Typography>
      <Button disabled={!next} onClick={advance}>
        Далее
      </Button>
    </Stack>
  );
}
export function useCollection<T>(
  url: string,
  refreshKey?: unknown,
  enabled = true,
) {
  const [items, setItems] = useState<T[]>([]),
    [state, setState] = useState({ url, index: 0, cursors: [""] }),
    [next, setNext] = useState(""),
    [error, setError] = useState(""),
    [loading, setLoading] = useState(false);
  const current = state.url === url ? state : { url, index: 0, cursors: [""] };
  const cursor = current.cursors[current.index] || "";
  useEffect(() => {
    setState({ url, index: 0, cursors: [""] });
    setNext("");
  }, [url]);
  const endpoint =
    url +
    (url.includes("?") ? "&" : "?") +
    "limit=100&after=" +
    encodeURIComponent(cursor);
  const reload = useCallback(async () => {
    if (!enabled) return;
    const result = await page<T>(endpoint);
    setItems(result.items);
    setNext(result.next);
    setError("");
  }, [endpoint, enabled]);
  useEffect(() => {
    let active = true;
    if (!enabled) {
      setItems([]);
      return;
    }
    setLoading(true);
    void page<T>(endpoint)
      .then((result) => {
        if (active) {
          setItems(result.items);
          setNext(result.next);
          setError("");
        }
      })
      .catch((e) => {
        if (active) setError(e.message);
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [endpoint, refreshKey, enabled]);
  return {
    items,
    error,
    reload,
    loading,
    index: current.index,
    next: state.url === url ? next : "",
    previous: () =>
      setState({ ...current, index: Math.max(0, current.index - 1) }),
    advance: () => {
      if (next)
        setState({
          ...current,
          cursors: [...current.cursors.slice(0, current.index + 1), next],
          index: current.index + 1,
        });
    },
  };
}
export function usePageNavigation() {
  const [index, setIndex] = useState(0),
    [cursors, setCursors] = useState([""]),
    [next, setNext] = useState("");
  return {
    index,
    after: cursors[index] || "",
    setNext,
    reset: () => {
      setIndex(0);
      setCursors([""]);
      setNext("");
    },
    controls: {
      index,
      next: !!next,
      previous: () => setIndex((i) => Math.max(0, i - 1)),
      advance: () => {
        setCursors((old) => [...old.slice(0, index + 1), next]);
        setIndex((i) => i + 1);
      },
    },
  };
}
