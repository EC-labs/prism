import React from "react";
import ReactDOM from "react-dom/client";
import MonacoSqlEditor from "./MonacoSqlEditor";
import { withStreamlitConnection } from "streamlit-component-lib";

// Wrap the component with Streamlit connection
const StreamlitMonacoSqlEditor = withStreamlitConnection(MonacoSqlEditor);

const root = ReactDOM.createRoot(
  document.getElementById("root") as HTMLElement
);

root.render(
  <React.StrictMode>
    <StreamlitMonacoSqlEditor />
  </React.StrictMode>
);
