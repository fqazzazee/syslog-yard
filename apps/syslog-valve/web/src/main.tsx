import React from "react";
import ReactDOM from "react-dom/client";
import "../../../shared/web/src/tokens.css";
import "../../../shared/web/src/components.css";
import "../../../shared/web/src/shell.css";
import "./styles.css";
import App from "./App";
import { initTheme } from "../../../shared/web/src/theme";

initTheme("valve");

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
