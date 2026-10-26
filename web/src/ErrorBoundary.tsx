import { Component, type ReactNode } from "react";
import { Alert, Button, Stack } from "@mui/material";

export class ErrorBoundary extends Component<
  { children: ReactNode; resetKey?: string },
  { error: string }
> {
  state = { error: "" };
  static getDerivedStateFromError(error: Error) {
    return { error: error.message };
  }
  componentDidUpdate(
    previous: Readonly<{ children: ReactNode; resetKey?: string }>,
  ) {
    if (previous.resetKey !== this.props.resetKey && this.state.error)
      this.setState({ error: "" });
  }
  render() {
    if (this.state.error)
      return (
        <Stack gap={2} sx={{ p: 3 }}>
          <Alert severity="error">
            Не удалось отобразить страницу: {this.state.error}
          </Alert>
          <Button onClick={() => window.location.reload()}>
            Перезагрузить
          </Button>
        </Stack>
      );
    return this.props.children;
  }
}
