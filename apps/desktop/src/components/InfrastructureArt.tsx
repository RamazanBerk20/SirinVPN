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
          <stop stopColor="#16e7ff" />
          <stop offset=".55" stopColor="#4559ff" />
          <stop offset="1" stopColor="#c524ff" />
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
            fill="#122a64"
            stroke={`url(#${id})`}
          />
          <path
            d="M0 15 143 0 143 39 0 54Z"
            fill="#060f29"
            stroke={`url(#${id})`}
            strokeWidth="2"
          />
          <path
            d="M143 0 177 19 177 58 143 39Z"
            fill="#111c48"
            stroke="#4951bb"
          />
          <path d="m16 29 80-8m-80 14 80-8" stroke="#1a4981" strokeWidth="3" />
          <circle cx="125" cy="21" r="3" fill="#0bf7ce" />
        </g>
      ))}
      <path
        d="m223 113 41 18v33c0 30-41 54-41 54s-41-24-41-54v-33Z"
        fill="#112464"
        stroke={`url(#${id})`}
        strokeWidth="3"
      />
      <rect x="207" y="156" width="32" height="26" rx="5" fill="#9eaeff" />
      <path
        d="M213 156v-9a10 10 0 0 1 20 0v9"
        fill="none"
        stroke="#bfeaff"
        strokeWidth="5"
      />
      <circle cx="223" cy="166" r="3" fill="#283074" />
      <path d="M223 168v6" stroke="#283074" strokeWidth="3" />
    </svg>
  );
}
