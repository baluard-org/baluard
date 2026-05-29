import { render } from "solid-js/web";
import { I18nProvider } from "./i18n/index.jsx";
import App from "./App";
import "./app.css";

render(() => <I18nProvider><App /></I18nProvider>, document.getElementById("root"));
