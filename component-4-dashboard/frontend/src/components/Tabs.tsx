import { useRef, type KeyboardEvent } from "react";

export type TabDef = { id: string; label: string };

/**
 * WAI-ARIA tabs: Left/Right arrows move between tabs, Home/End jump to the
 * ends, and only the selected tab is in the Tab order (roving tabindex).
 */
export function Tabs({ tabs, selected, onSelect }: { tabs: TabDef[]; selected: string; onSelect: (id: string) => void }) {
  const refs = useRef<(HTMLButtonElement | null)[]>([]);

  const onKeyDown = (e: KeyboardEvent<HTMLButtonElement>, index: number) => {
    let next = index;
    if (e.key === "ArrowRight") next = (index + 1) % tabs.length;
    else if (e.key === "ArrowLeft") next = (index - 1 + tabs.length) % tabs.length;
    else if (e.key === "Home") next = 0;
    else if (e.key === "End") next = tabs.length - 1;
    else return;
    e.preventDefault();
    onSelect(tabs[next].id);
    refs.current[next]?.focus();
  };

  return (
    <div className="tabs" role="tablist" aria-label="Dashboard sections">
      {tabs.map((t, i) => (
        <button
          key={t.id}
          ref={(el) => { refs.current[i] = el; }}
          role="tab"
          id={`tab-${t.id}`}
          aria-selected={t.id === selected}
          aria-controls={`panel-${t.id}`}
          tabIndex={t.id === selected ? 0 : -1}
          className="tab"
          onClick={() => onSelect(t.id)}
          onKeyDown={(e) => onKeyDown(e, i)}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}
