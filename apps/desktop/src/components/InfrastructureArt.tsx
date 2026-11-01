import { useId } from "react";

/** Local vector decoration: never contains a location or live network data. */
export function InfrastructureArt() {
  const id = useId();
  return (
    <svg
      className="infrastructure-art"
      viewBox="0 0 320 235"
      aria-hidden="true"
    >
      <defs>
        <linearGradient id={id} x2="1" y2="1">
          <stop className="art-cyan" />
          <stop offset=".55" className="art-accent" />
          <stop offset="1" className="art-violet" />
        </linearGradient>
      </defs>
      <ellipse
        cx="162"
        cy="202"
        rx="146"
        ry="20"
        fill="none"
        stroke={`url(#${id})`}
        opacity=".65"
      />
      {[0, 1, 2].map((i) => (
        <g key={i} transform={`translate(62 ${28 + i * 49})`}>
          <path
            d="M0 15 143 0 177 19 34 38Z"
            className="art-top"
            stroke={`url(#${id})`}
          />
          <path
            d="M0 15 143 0 143 39 0 54Z"
            className="art-front"
            stroke={`url(#${id})`}
            strokeWidth="2"
          />
          <path
            d="M143 0 177 19 177 58 143 39Z"
            className="art-side"
          />
          <path d="m16 29 80-8m-80 14 80-8" className="art-slots" strokeWidth="3" />
          <circle cx="125" cy="21" r="3" className="art-led" />
        </g>
      ))}
      <path
        d="m223 113 41 18v33c0 30-41 54-41 54s-41-24-41-54v-33Z"
        className="art-shield"
        stroke={`url(#${id})`}
        strokeWidth="3"
      />
      <rect x="207" y="156" width="32" height="26" rx="5" className="art-lock" />
      <path
        d="M213 156v-9a10 10 0 0 1 20 0v9"
        fill="none"
        className="art-shackle"
        strokeWidth="5"
      />
      <circle cx="223" cy="166" r="3" className="art-keyhole" />
      <path d="M223 168v6" className="art-keyhole" strokeWidth="3" />
    </svg>
  );
}
