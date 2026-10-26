import { useState } from "react";
import {
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import { NodeHealth } from "./NodeHealth";
import { api, can, date } from "./api";
import type { Me, Node } from "./types";
export function NodeDetails({
  node,
  me,
  close,
  act,
}: {
  node: Node;
  me: Me;
  close: () => void;
  act: (fn: () => Promise<unknown>) => Promise<void>;
}) {
  const [host, setHost] = useState(node.ssh_host || node.hostname || node.name),
    [port, setPort] = useState(node.ssh_port || 22);
  return (
    <Dialog open onClose={close} fullWidth maxWidth="sm">
      <DialogTitle>{node.name}</DialogTitle>
      <DialogContent>
        <Stack gap={3} pt={1}>
          <NodeHealth node={node} />
          <Typography>
            Hostname: {node.hostname || "Не получен от агента"}
          </Typography>
          <Typography>
            IP: {node.addresses?.join(", ") || "Не получены от агента"}
          </Typography>
          <Typography>
            ОС: {node.platform || "—"} · Обновлено: {date(node.metadata_seen)}
          </Typography>
          <Typography>Группа: {node.group_name}</Typography>
          <Typography>
            Сертификат: {node.certificate_status === "expired" ? "истёк; требуется восстановление"
              : node.certificate_status === "pending" ? "ожидает перевыпуска" : "актуальный"}.
            Срок действия: {date(node.cert_expires)}
          </Typography>
          <Typography variant="body2" className="mono">
            ID: {node.id}
          </Typography>
          <TextField
            label="SSH hostname / IP для Ansible"
            value={host}
            disabled={!can(me, "nodes.manage", node.group_id)}
            onChange={(e) => setHost(e.target.value)}
          />
          <TextField
            type="number"
            label="SSH порт"
            value={port}
            disabled={!can(me, "nodes.manage", node.group_id)}
            onChange={(e) => setPort(Number(e.target.value))}
          />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={close}>Закрыть</Button>
        {can(me, "nodes.manage", node.group_id) && (
          <Button
            disabled={!host || port < 1 || port > 65535}
            onClick={() =>
              void act(async () => {
                await api(`/nodes/${node.id}/ssh`, "PUT", { host, port });
                close();
              })
            }
          >
            Сохранить
          </Button>
        )}
      </DialogActions>
    </Dialog>
  );
}
