import { useEffect, useRef } from "react";
import { usePreferences } from "../features/settings/PreferencesProvider";

/** Animate the existing page, preserving forms and in-flight operations. */
export function usePageTransition<T extends HTMLElement>(page: string) {
  const element = useRef<T>(null);
  const { snapshot } = usePreferences();
  const animations = snapshot?.preferences.animations !== false;
  useEffect(() => {
    if (
      !animations ||
      window.matchMedia?.("(prefers-reduced-motion: reduce)").matches
    )
      return;
    const animation = element.current?.animate?.(
      [
        { opacity: 0.45, transform: "translateY(5px)" },
        { opacity: 1, transform: "translateY(0)" },
      ],
      { duration: 180, easing: "ease-out" },
    );
    return () => animation?.cancel();
  }, [page, animations]);
  return element;
}
