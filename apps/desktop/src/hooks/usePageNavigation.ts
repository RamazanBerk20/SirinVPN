import { confirmNavigation } from "../lib/navigationGuard";
import { useCallback, useEffect, useRef, useState } from "react";
import type { Page } from "../components/Navigation";
import { pageScrollPort } from "../lib/scrolling";

const pages: Page[] = ["home", "servers", "devices", "settings"];
const details: Partial<Record<Page, string[]>> = {
  home: ["details", "connection"],
  settings: ["general", "connection", "network", "recovery", "maintenance", "advanced"],
};
function readRoute(): [Page, string] {
  const [value, detail] = window.location.hash.slice(1).split("/");
  const page = pages.includes(value as Page) ? value as Page : "home";
  return [page, details[page]?.includes(detail) ? detail : ""];
}
/** History contains only screen names, never profiles or secret material. */
export function usePageNavigation(): [Page, (next: Page, detail?: string) => void, string, () => void] {
  const [[page, detail], setRoute] = useState(readRoute);
  const shown = useRef(`#${page}${detail ? `/${detail}` : ""}`);
  shown.current = `#${page}${detail ? `/${detail}` : ""}`;
  useEffect(() => {
    if (window.history.state?.sirinDepth === undefined)
      window.history.replaceState({ ...window.history.state, sirinDepth: 0 }, "");
    const port = pageScrollPort();
    if (
      port === window
        ? window.scrollY !== 0
        : (port as HTMLElement).scrollTop !== 0
    )
      port.scrollTo({ top: 0, behavior: "instant" });
  }, [page, detail]);
  useEffect(() => {
    // Browser and mouse Back arrive here after the URL already changed: a guard that refuses puts the shown page back.
    const onBack = () => {
      if (!confirmNavigation()) {
        window.history.pushState({ sirinDepth: (window.history.state?.sirinDepth ?? 0) + 1 }, "", shown.current);
        return;
      }
      setRoute(readRoute());
    };
    window.addEventListener("popstate", onBack);
    return () => window.removeEventListener("popstate", onBack);
  }, []);
  const navigate = useCallback(
    (next: Page, section = "") => {
      const nextDetail = details[next]?.includes(section) ? section : "";
      if ((next === page && nextDetail === detail) || !confirmNavigation()) return;
      window.history.pushState({ sirinDepth: (window.history.state?.sirinDepth ?? 0) + 1 }, "", `#${next}${nextDetail ? `/${nextDetail}` : ""}`);
      setRoute([next, nextDetail]);
    },
    [page, detail],
  );
  const back = useCallback(() => {
    if (!confirmNavigation()) return;
    if (window.history.state?.sirinDepth > 0) window.history.back();
    else {
      window.history.replaceState({ sirinDepth: 0 }, "", `#${page}`);
      setRoute([page, ""]);
    }
  }, [page]);
  return [page, navigate, detail, back];
}
