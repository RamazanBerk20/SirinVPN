import React from "react";
import ReactDOM from "react-dom/client";
import "@fontsource-variable/inter";
import "@fontsource-variable/jetbrains-mono";
import "./styles.css";
import App from "./App";
import { isAndroid, isDemo } from "./platform";
import { DemoBanner } from "./components/DemoBanner";
import { useLocale } from "./i18n";
import { initLanguage } from "./i18n/language";
import "./styles/mobile-native.css";
if (isAndroid) document.documentElement.classList.add("android");

/** Re-renders the whole interface when the language changes, keeping its state. */
function Root() {
  useLocale();
  return <>
    <App />
    {isDemo && <DemoBanner />}
  </>;
}

// The saved language loads before the first render, so translated text never flashes English first.
void initLanguage().finally(() => ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <Root />
  </React.StrictMode>,
));
