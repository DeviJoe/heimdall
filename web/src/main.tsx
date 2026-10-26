import React from "react";
import ReactDOM from "react-dom/client";
import { CssBaseline, ThemeProvider, createTheme } from "@mui/material";
import { App } from "./App";
import { ErrorBoundary } from "./ErrorBoundary";
import "./style.css";
const theme = createTheme({
  palette: {
    primary: { main: "#155ac8" },
    secondary: { main: "#57657b" },
    background: { default: "#f5f7fb", paper: "#ffffff" },
    success: { main: "#137348" },
    error: { main: "#b3261e" },
  },
  shape: { borderRadius: 16 },
  typography: {
    fontFamily:
      'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
    h4: { fontWeight: 700, letterSpacing: "-0.8px" },
    h5: { fontWeight: 650 },
    button: { textTransform: "none", fontWeight: 600 },
  },
  components: {
    MuiButton: {
      defaultProps: { disableElevation: true },
      styleOverrides: { root: { borderRadius: 24, padding: "10px 20px" } },
    },
    MuiPaper: { defaultProps: { elevation: 0 } },
    MuiDialog: { styleOverrides: { paper: { borderRadius: 24 } } },
    MuiTextField: { defaultProps: { size: "small", fullWidth: true } },
    MuiChip: { styleOverrides: { root: { fontWeight: 600 } } },
  },
});
ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <ErrorBoundary>
        <App />
      </ErrorBoundary>
    </ThemeProvider>
  </React.StrictMode>,
);
