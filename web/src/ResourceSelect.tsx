import { useEffect, useState } from "react";
import { Autocomplete, TextField } from "@mui/material";
import { useCollection } from "./Pagination";
type Option = {
  id: string;
  name?: string;
  login?: string;
  display_name?: string;
};
export function ResourceSelect({
  resource,
  label,
  value,
  onChange,
  initialLabel,
  disabled = false,
  allowRoot = false,
  extraOptions = [],
}: {
  resource: string;
  label: string;
  value: string;
  onChange: (id: string) => void;
  initialLabel?: string;
  disabled?: boolean;
  allowRoot?: boolean;
  extraOptions?: Option[];
}) {
  const [open, setOpen] = useState(false);
  const [input, setInput] = useState(""),
    [query, setQuery] = useState(""),
    [selected, setSelected] = useState<Option | null>(
      value ? { id: value, name: initialLabel || value } : null,
    );
  useEffect(() => {
    const timer = setTimeout(() => setQuery(input), 250);
    return () => clearTimeout(timer);
  }, [input]);
  useEffect(() => {
    if (!value) setSelected(null);
    else if (selected?.id !== value)
      setSelected({ id: value, name: initialLabel || value });
  }, [value, initialLabel]);
  const choices = useCollection<Option>(
    resource +
      (resource.includes("?") ? "&" : "?") +
      "query=" +
      encodeURIComponent(query),
  );
  const options = [
    ...(allowRoot ? [{ id: "", name: "Корень" }] : []),
    ...extraOptions,
    ...choices.items.filter((o) => !extraOptions.some((e) => e.id === o.id)),
    ...(choices.index
      ? [{ id: "__previous", name: "← Предыдущая страница" }]
      : []),
    ...(choices.next ? [{ id: "__next", name: "Следующая страница →" }] : []),
  ];
  return (
    <Autocomplete
      open={open}
      onOpen={() => setOpen(true)}
      onClose={() => setOpen(false)}
      loadingText="Загрузка…"
      noOptionsText="Нет подходящих записей"
      disableCloseOnSelect
      loading={choices.loading}
      fullWidth
      disabled={disabled}
      value={selected}
      options={options}
      filterOptions={(options) => options}
      isOptionEqualToValue={(a, b) => a.id === b.id}
      getOptionLabel={(o) => o.name || `${o.login} · ${o.display_name || ""}`}
      onInputChange={(_, text, reason) => {
        if (reason === "input") {
          setInput(text);
        } else if (reason === "clear") setInput("");
      }}
      onChange={(_, option) => {
        if (option?.id === "__next") {
          choices.advance();
          return;
        }
        if (option?.id === "__previous") {
          choices.previous();
          return;
        }
        setOpen(false);
        setSelected(option);
        onChange(option?.id || "");
      }}
      renderInput={(params) => (
        <TextField
          {...params}
          label={label}
          error={!!choices.error}
          helperText={choices.error || undefined}
        />
      )}
    />
  );
}
