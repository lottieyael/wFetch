export function InfoCard({ title, children, id }) {
  return (
    <div className="info-card" id={id}>
      <div className="card-header">
        <h2 className="card-title">{title}</h2>
      </div>
      <div className="card-content">{children}</div>
    </div>
  );
}

export function InfoRow({ label, value, extra }) {
  return (
    <div className="info-item">
      {label && <span className="info-label">{label}</span>}
      <span className="info-value">
        {value}
        {extra && <span className="vram"> ({extra})</span>}
      </span>
    </div>
  );
}

export function ProgressBar({ percent }) {
  return (
    <div className="progress-container">
      <div
        className="progress-bar"
        style={{
          width: `${percent}%`,
        }}
      >
        <div className="progress-shine"></div>
      </div>
    </div>
  );
}

export function FadingText({ text, startDelay = 0, step = 20 }) {
  const chars = Array.from(text);
  return (
    <span className="fading-text" aria-label={text}>
      {chars.map((ch, i) => (
        <span
          key={i}
          className="ai-char"
          style={{ animationDelay: `${startDelay + i * step}ms` }}
        >
          {ch === " " ? "\u00A0" : ch}
        </span>
      ))}
    </span>
  );
}
