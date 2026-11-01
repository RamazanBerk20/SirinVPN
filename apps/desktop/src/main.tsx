import React from "react";
import ReactDOM from "react-dom/client";
import "@fontsource-variable/inter";
import "@fontsource-variable/jetbrains-mono";
import "./styles.css";
import App from "./App";
import { isAndroid, isDemo } from "./platform";
import { DemoBanner } from "./components/DemoBanner";
import "./styles/mobile-native.css";
if (isAndroid) document.documentElement.classList.add("android");

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
    {isDemo && <DemoBanner />}
  </React.StrictMode>,
);
void import("./i18n/native").then(native => native.pushNativeText(), () => {});
