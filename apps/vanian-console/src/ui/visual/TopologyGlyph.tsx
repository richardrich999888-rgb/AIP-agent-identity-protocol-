import { useId } from "react";
import type { NodeKind } from "./model";

/** Optical symbols for the default investigation diagram. */
export function DiagramGlyph({ kind }: { kind: NodeKind }) {
  const paths: Record<NodeKind, React.ReactNode> = {
    human: (
      <>
        <circle cx="12" cy="8" r="3.15" />
        <path d="M5 19c.45-3.2 2.95-5.4 7-5.4s6.55 2.2 7 5.4" />
      </>
    ),
    agent: (
      <>
        <path d="m12 3 7.1 4.1v8.2L12 19.4l-7.1-4.1V7.1z" />
        <path d="m5.2 7.4 6.8 4 6.8-4M12 11.4v8" />
        <path d="m9.5 4.4 7 4.1" />
      </>
    ),
    process: (
      <>
        <rect x="5.7" y="5.7" width="12.6" height="12.6" rx="2.1" />
        <rect x="9" y="9" width="6" height="6" rx=".8" />
        <path d="M9 3v2m6-2v2M3 9h2m-2 6h2m4 4v2m6-2v2m4-12h2m-2 6h2" />
      </>
    ),
    workload: (
      <>
        <path d="m12 4 8 4.3-8 4.3-8-4.3zM4 12.3l8 4.3 8-4.3M4 16.3l8 4.3 8-4.3" />
      </>
    ),
    service: (
      <>
        <rect x="4" y="4.5" width="16" height="6.2" rx="1.4" />
        <rect x="4" y="13.3" width="16" height="6.2" rx="1.4" />
        <path d="M7 7.5h2m-2 9h2" />
      </>
    ),
    tool: (
      <>
        <path d="m12.2 11.3-7.9 7.9a1.5 1.5 0 0 0 2.1 2.1l8-8" />
        <path d="M12.2 11.3a5.5 5.5 0 0 1 6.5-7.7L16 6.3l.7 2.4 2.4.7 2.7-2.7a5.5 5.5 0 0 1-7.4 6.6" />
      </>
    ),
    action: (
      <>
        <path d="M4.5 13h7.8V7.7L20 13l-7.7 5.3v-3.1H6.5" />
        <path d="M4.5 8.4h4.6" />
      </>
    ),
    evidence: (
      <>
        <path d="M6 3.5h9l3 3.4v13.6H6zM14.2 3.7v4h3.4m-8.3 3.5h5.5m-5.5 3.4h4.2" />
      </>
    ),
    unknown: (
      <>
        <path d="M6 8V5h3m6 0h3v3m0 8v3h-3m-6 0H6v-3" />
        <path d="M10 10a2.2 2.2 0 1 1 3.3 1.9c-.9.5-1.3.8-1.3 1.8m0 2.6h.01" />
      </>
    ),
  };
  return (
    <svg
      className="vgraph-diagram-glyph"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.65"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {paths[kind] ?? paths.unknown}
    </svg>
  );
}

/** Small axonometric components. Their silhouettes encode record type only. */
export function TopologyGlyph({ kind }: { kind: NodeKind }) {
  const id = useId().replace(/[^a-zA-Z0-9_-]/g, "");
  const metal = "url(#" + id + "-metal)",
    rim = "url(#" + id + "-rim)",
    core = "url(#" + id + "-core)",
    ink = "#36215d",
    light = "#eedfff";
  const chip = () => (
    <>
      <path d="m6 30 16-10 20 10-19 11z" fill={ink} />
      <path d="m6 27 17-10 19 10-19 11z" fill={metal} stroke={rim} />
      <path d="M23 38v4l19-11v-4z" fill="#513288" />
      {[0, 1, 2, 3].map((i) => (
        <g key={i} stroke={rim} strokeWidth="1.6" strokeLinecap="round">
          <path d={"m" + (9 + i * 4) + " " + (29 + i * 2.2) + " -3 2"} />
          <path d={"m" + (28 + i * 3) + " " + (20 + i * 1.5) + " 3 -2"} />
        </g>
      ))}
      <path d="m14 24 9-5 11 6-11 6z" fill={light} />
      <path d="m14 24 9 5 11-5v4l-11 6-9-6z" fill={core} />
      <path d="m18 24 5-2.6 5.3 2.9-5.4 3z" fill="#8a58f8" />
    </>
  );
  const blocks = (quantity: number) =>
    Array.from({ length: quantity }, (_, i) => (
      <g key={i} transform={"translate(0," + -6 * i + ")"}>
        <path d="m9 31 13-7 17 8-14 9z" fill={metal} />
        <path d="m9 31 16 8 14-7v4l-14 8-16-8z" fill={ink} />
        <path d="m25 39 14-7v3l-14 8z" fill="#7446ad" />
        <path d="m13 35 5 2.5" stroke={rim} strokeWidth="1.4" />
      </g>
    ));
  const shapes: Record<NodeKind, () => React.ReactNode> = {
    human: () => (
      <>
        <g transform="rotate(-22 24 25)">
          <ellipse
            cx="24"
            cy="24"
            rx="15"
            ry="18"
            fill="none"
            stroke={rim}
            strokeWidth="1.5"
          />
          <path
            d="M10 29a15 18 0 0 1 23-20"
            fill="none"
            stroke={light}
            strokeWidth="1"
          />
        </g>
        <path
          d="M11 34c.5-6.5 7-10.5 13-10.5S36 28 37.5 34l-12.8 7z"
          fill={metal}
        />
        <path d="m17 28 6.6 4.2 7-4.8-2.1 8.2-4.7 2.9-4.8-3.7z" fill={core} />
        <path
          d="m17.1 15.5 2.6-5.3 6.3-1.6 6.3 4.3-.8 8.3-6.6 5.5-7.1-5z"
          fill={metal}
          stroke={rim}
          strokeWidth=".65"
        />
        <path d="m19.6 15 9.9-1.1-1.5 5.3-6.4 1.1z" fill="#382360" />
        <path d="m21 16.7 6.5-.8" stroke={light} />
      </>
    ),
    agent: () => (
      <>
        <path
          d="m24 8 11 16-10.9 13L13 23z"
          fill={metal}
          stroke={rim}
          strokeWidth=".8"
        />
        <path d="m24 8-2.4 15.2L13 23z" fill={light} />
        <path d="m24 8 11 16-13.4-.8z" fill={core} />
        <path d="m21.6 23.2 2.5 13.8-11-14z" fill="#6f46bc" />
        <ellipse
          transform="rotate(-33 24 24)"
          cx="24"
          cy="24"
          rx="19"
          ry="8"
          fill="none"
          stroke={rim}
          strokeWidth="2.3"
        />
        <path
          d="M9.7 31.2c3.5 2.6 11.9.2 20.7-5.2"
          fill="none"
          stroke="white"
          strokeWidth="1.35"
        />
        <circle cx="38.7" cy="14.8" r="2.15" fill={light} stroke="#8756d5" />
      </>
    ),
    process: chip,
    workload: () => <>{blocks(3)}</>,
    service: () => (
      <>
        <path d="m7 35 17-9 17 9-16 9z" fill={ink} />
        {[
          [12, 14, 13, 22],
          [22, 9, 13, 25],
        ].map(([x, y, w, h]) => (
          <g key={x}>
            <path d={"M" + x + " " + y + "l6-4 7 4-6 4z"} fill={rim} />
            <path
              d={"M" + x + " " + y + "l7 4v" + (h - 4) + "l-7-4z"}
              fill={metal}
            />
            <path
              d={"M" + (x + 7) + " " + (y + 4) + "l6-4v" + (h - 4) + "l-6 4z"}
              fill={ink}
            />
            {[0, 1, 2].map((i) => (
              <path
                key={i}
                d={"M" + (x + 2) + " " + (y + 5 + i * 3) + "l3 1.6"}
                stroke={light}
                strokeWidth=".7"
              />
            ))}
          </g>
        ))}
      </>
    ),
    tool: () => (
      <>
        <path d="m10 32 4 7 7-.5 8-14-6-5z" fill={metal} stroke={rim} />
        <path d="m16 33 10-12 2.2 2-9 13-3.4.2z" fill={ink} />
        <path
          d="m24 23-4-7 4-8 7-2-4 7 3.5 3 4.4-.3 4.6-6 1 6-3.6 6.5-7.9 2.7z"
          fill={metal}
          stroke={rim}
        />
        <circle
          cx="15"
          cy="34.6"
          r="2.2"
          fill={ink}
          stroke={light}
          strokeWidth=".7"
        />
      </>
    ),
    action: () => (
      <>
        <path d="m8 28 10-6-5-7 24 1.5L29 37l-5-8-11 6z" fill={ink} />
        <path
          d="m8 24 10-6-5-7 24 1.5L29 33l-5-8-11 6z"
          fill={metal}
          stroke={rim}
        />
        <path d="m13 11 24 1.5-11.3 7-7.7-1.5z" fill={light} />
        <path d="m26 20 11-7.5L29 33z" fill={core} />
      </>
    ),
    evidence: () => (
      <>
        <path
          d="m10 14 14-7.5 14 7.5v19l-14 9-14-9z"
          fill={metal}
          stroke={rim}
        />
        <path d="m10 14 14 7 14-7-14-7.5z" fill={light} />
        <path d="m24 21 14-7v19l-14 9z" fill={ink} />
        <path d="m17 10.5 14.4 7.2v12l-4 2.6V20l-14-7z" fill={core} />
        <path d="m13 24 8 4m-8 0 5 2.5" stroke={light} strokeWidth="1.1" />
      </>
    ),
    unknown: () => (
      <>
        <path
          d="m21 8-13 12 9 4 6-9zM27 8l13 13-9 1-5-8zM7 25l12 14 3-8-5-5zM26 39l14-13-7-1-7 8z"
          fill={metal}
          stroke={rim}
          strokeWidth=".9"
        />
        <path d="m21 23 3-3 3 3-3 4z" fill={light} />
      </>
    ),
  };
  return (
    <svg
      aria-hidden="true"
      viewBox="0 0 48 48"
      className="vgraph-glyph"
      focusable="false"
    >
      <defs>
        <linearGradient id={id + "-metal"} x1="0" y1="0" x2=".8" y2="1">
          <stop stopColor="#fff2ff" />
          <stop offset=".27" stopColor="#cfb1fa" />
          <stop offset=".51" stopColor="#8a67bd" />
          <stop offset=".78" stopColor="#523778" />
          <stop offset="1" stopColor="#322045" />
        </linearGradient>
        <linearGradient id={id + "-rim"} x1="0" y1="0" x2="1" y2="1">
          <stop stopColor="#f3d8ff" />
          <stop offset=".45" stopColor="#ad7deb" />
          <stop offset="1" stopColor="#6842a1" />
        </linearGradient>
        <linearGradient id={id + "-core"} x1="0" y1="0" x2="1" y2="1">
          <stop stopColor="#ecc7ff" />
          <stop offset=".42" stopColor="#ad68fc" />
          <stop offset="1" stopColor="#6730d0" />
        </linearGradient>
      </defs>
      {(shapes[kind] ?? shapes.unknown)()}
    </svg>
  );
}
