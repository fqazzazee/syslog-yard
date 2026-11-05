import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "../../../shared/web/src/tokens.css";
import "../../../shared/web/src/components.css";
import "../../../shared/web/src/shell.css";
import "./styles.css";
import App from "./App";
import { initTheme } from "../../../shared/web/src/theme";

initTheme("bucket");

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
