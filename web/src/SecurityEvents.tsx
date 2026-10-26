import { useState } from "react";
import {
  Alert,
  TableCell,
  TableRow,
  TextField,
  Typography,
} from "@mui/material";
import { date } from "./api";
import { DataTable } from "./common";
import { Pagination, useCollection } from "./Pagination";
type Event = {
  id: string;
  node_id: string;
  node_name: string;
  login: string;
  address: string;
  kind: string;
  severity: string;
  observed_at: string;
};
export function SecurityEvents() {
  const [search, setSearch] = useState("");
  const events = useCollection<Event>(
    "/security/events?query=" + encodeURIComponent(search),
  );
  return (
    <>
      <Typography variant="h6" my={2}>
        SSH-события
      </Typography>
      <TextField
        fullWidth
        label="Поиск событий: нода, логин, IP"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        sx={{ mb: 2 }}
      />
      {events.error && <Alert severity="error">{events.error}</Alert>}
      <DataTable
        heads={["Время", "Нода", "Логин", "Адрес", "Событие"]}
        empty={!events.items.length}
      >
        {events.items.map((e) => (
          <TableRow key={e.node_id + e.id}>
            <TableCell>{date(e.observed_at)}</TableCell>
            <TableCell>{e.node_name || "Нода удалена"}</TableCell>
            <TableCell>{e.login}</TableCell>
            <TableCell>{e.address}</TableCell>
            <TableCell>
              {e.kind} · {e.severity}
            </TableCell>
          </TableRow>
        ))}
      </DataTable>
      <Pagination {...events} next={!!events.next} />
    </>
  );
}
