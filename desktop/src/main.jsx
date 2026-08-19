import { render } from "@solidjs/web";
import { I18nProvider } from "./i18n/index.jsx";
import { AuthProvider } from "./context/AuthContext.jsx";
import App from "./App";
import "./app.css";

render(() => <I18nProvider><AuthProvider><App /></AuthProvider></I18nProvider>, document.getElementById("root"));
