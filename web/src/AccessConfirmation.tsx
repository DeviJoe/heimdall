import { useEffect, useRef, useState, type ReactNode } from "react";
import {
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Typography,
} from "@mui/material";
import { installAccessConfirmation } from "./api";
import type { AccessAction } from "./accessActions";

export function AccessConfirmation({ children }: { children: ReactNode }) {
  const [action, setAction] = useState<AccessAction | null>(null);
  const pending = useRef<((approved: boolean) => void) | null>(null);
  const decide = (approved: boolean) => {
    pending.current?.(approved);
    pending.current = null;
    setAction(null);
  };
  useEffect(() => {
    const uninstall = installAccessConfirmation(
      (requested) =>
        new Promise<boolean>((resolve) => {
          // Do not replace an unconfirmed operation with another concurrent action.
          if (pending.current) {
            resolve(false);
            return;
          }
          pending.current = resolve;
          setAction(requested);
        }),
    );
    return () => {
      uninstall();
      pending.current?.(false);
      pending.current = null;
    };
  }, []);
  return (
    <>
      {children}
      <Dialog
        open={!!action}
        onClose={() => decide(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>{action?.title}</DialogTitle>
        <DialogContent>
          <Typography>{action?.message}</Typography>
        </DialogContent>
        <DialogActions>
          <Button autoFocus onClick={() => decide(false)}>
            Отмена
          </Button>
          <Button
            color="error"
            variant="contained"
            onClick={() => decide(true)}
          >
            {action?.confirmLabel}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
}
