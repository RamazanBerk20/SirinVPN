import { useEffect, useRef, useState } from "react";

/** Avoid uneven QR cells when a dense invitation is scaled to fit the window. */
export function InvitationQr({ source, enlarged = false, kind = "invitation" }: { source: string; enlarged?: boolean; kind?: "invitation" | "recovery" }) {
  const frame = useRef<HTMLDivElement>(null);
  const [modules, setModules] = useState(0);
  const [size, setSize] = useState<number>();

  useEffect(() => {
    const element = frame.current;
    if (!element || !modules) return;
    const dialog = enlarged ? element.closest<HTMLElement>(".invitation-qr-dialog") : null;
    const body = dialog?.querySelector<HTMLElement>(".dialog-body");
    const header = dialog?.querySelector<HTMLElement>(".dialog-header");
    const footer = dialog?.querySelector<HTMLElement>(".dialog-footer");
    const resize = () => {
      let available = element.getBoundingClientRect().width;
      if (dialog && body) {
        const chrome = getComputedStyle(dialog), content = getComputedStyle(body);
        const maximum = Number.parseFloat(chrome.maxHeight);
        if (Number.isFinite(maximum)) {
          const height = maximum - (header?.getBoundingClientRect().height ?? 0) - (footer?.getBoundingClientRect().height ?? 0)
            - Number.parseFloat(content.paddingTop) - Number.parseFloat(content.paddingBottom)
            - Number.parseFloat(chrome.borderTopWidth) - Number.parseFloat(chrome.borderBottomWidth);
          available = Math.min(available, Math.max(1, height));
        }
      }
      const scale = window.devicePixelRatio || 1;
      const pixelsPerModule = Math.floor(available * scale / modules);
      setSize(pixelsPerModule >= 1 ? pixelsPerModule * modules / scale : available);
    };
    resize();
    const observer = typeof ResizeObserver === "undefined" ? null : new ResizeObserver(resize);
    observer?.observe(element);
    if (header) observer?.observe(header);
    if (footer) observer?.observe(footer);
    window.addEventListener("resize", resize);
    return () => {
      observer?.disconnect();
      window.removeEventListener("resize", resize);
    };
  }, [modules, enlarged]);

  return (
    <div ref={frame} className={`invitation-qr-frame${enlarged ? " invitation-qr-enlarged" : ""}`}>
      <img
        src={source}
        style={{ width: size ?? "100%" }}
        onLoad={(event) => {
          // Fixture SVGs can use physical units; viewBox retains one unit per module.
          let count = event.currentTarget.naturalWidth;
          if (source.startsWith("data:image/svg+xml;charset=utf-8,")) {
            const svg = decodeURIComponent(source.slice(source.indexOf(",") + 1));
            const match = /viewBox=["']0 0 ([0-9]+) [0-9]+["']/.exec(svg);
            if (match) count = Number(match[1]);
          }
          setModules(count);
        }}
        alt={`${enlarged ? "Enlarged " : ""}SirinVPN ${kind} QR code`}
      />
    </div>
  );
}
