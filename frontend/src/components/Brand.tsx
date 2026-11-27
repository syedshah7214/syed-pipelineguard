import { useId } from "react";

/** SYED monogram: hexagon (infrastructure node) wrapping an S drawn as a circuit trace. */
export function Monogram({ size = 36, animated = false }: { size?: number; animated?: boolean }) {
  const id = useId().replace(/:/g, "");
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" role="img" aria-label="SYED" className={animated ? "mono mono--animated" : "mono"}>
      <defs>
        <linearGradient id={`m${id}`} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#FF7A1A" />
          <stop offset=".55" stopColor="#FF3D6E" />
          <stop offset="1" stopColor="#EC268F" />
        </linearGradient>
      </defs>
      <path className="mono__hex" d="M32 3 57 17.5v29L32 61 7 46.5v-29z" fill="#ffffff" stroke={`url(#m${id})`} strokeWidth="3" />
      <path className="mono__s" d="M42 22H28a5 5 0 0 0 0 10h8a5 5 0 0 1 0 10H22" fill="none" stroke={`url(#m${id})`} strokeWidth="4.5" strokeLinecap="round" strokeLinejoin="round" />
      <circle className="mono__node" cx="42" cy="22" r="3.2" fill="#FF7A1A" />
      <circle className="mono__node mono__node--b" cx="22" cy="42" r="3.2" fill="#EC268F" />
    </svg>
  );
}

export function Wordmark({ compact = false }: { compact?: boolean }) {
  return (
    <div className="wordmark">
      <span className="wordmark__name">SYED</span>
      {!compact && <span className="wordmark__divider" aria-hidden="true" />}
      {!compact && <span className="wordmark__product">PipelineGuard</span>}
    </div>
  );
}

/** Brief branded loader. It fades as soon as the first data arrives — it never adds an artificial delay. */
export function Splash({ leaving }: { leaving: boolean }) {
  return (
    <div className={`splash ${leaving ? "splash--leaving" : ""}`} role="status" aria-live="polite" aria-label="Loading PipelineGuard">
      <div className="splash__inner">
        <Monogram size={84} animated />
        <p className="splash__title">SYED <span>PipelineGuard</span></p>
        <p className="splash__sub">GitHub Actions Security Auditor</p>
        <div className="splash__bar" aria-hidden="true"><span /></div>
      </div>
    </div>
  );
}
