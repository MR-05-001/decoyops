interface Kpi {
  label: string;
  value: string | number;
  delta: string;
  tone?: "amber" | "red" | "default";
  deltaTone?: "up" | "default";
}

interface KpiStripProps {
  items: Kpi[];
}

const toneClass: Record<NonNullable<Kpi["tone"]>, string> = {
  amber: "text-dp-amber",
  red: "text-dp-red",
  default: "text-dp-text",
};

/**
 * Deliberately NOT the SaaS-card-kit pattern (identical rounded cards,
 * matching soft shadow). A single strip divided by hairlines reads as
 * one instrument panel, not four disconnected widgets.
 */
export function KpiStrip({ items }: KpiStripProps) {
  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 p-5 pb-0 bg-transparent">
      {items.map((kpi, _i) => (
        <div
          key={kpi.label}
          className="interactive-card p-5"
        >
          <div className="text-[11.5px] text-dp-text-faint mb-2 truncate uppercase tracking-wider">{kpi.label}</div>
          <div className={`font-mono text-2xl font-semibold tracking-tight ${toneClass[kpi.tone ?? "default"]}`}>
            {kpi.value}
          </div>
          <div
            className={`font-mono text-[11px] mt-1.5 ${
              kpi.deltaTone === "up" ? "text-dp-teal" : "text-dp-text-faint"
            }`}
          >
            {kpi.delta}
          </div>
        </div>
      ))}
    </div>
  );
}
