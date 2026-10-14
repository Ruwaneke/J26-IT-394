import React from 'react';

type CircleItem = { cx: number; cy: number; r: number };
type IconDef = Array<string | CircleItem>;

const or = 'M12 3l7 3v5c0 4.5-3 8.2-7 9.8C8 19.2 5 15.5 5 11V6l7-3z';
const sr: CircleItem = { cx: 12, cy: 12, r: 9 };

const icons: Record<string, IconDef> = {
  shield: [or],
  shieldCheck: [or, 'M9 12l2 2 4-4'],
  shieldAlert: [or, 'M12 8v4', 'M12 16h.01'],
  user: [{ cx: 12, cy: 8, r: 4 }, 'M4 21c0-4 3.6-7 8-7s8 3 8 7'],
  list: ['M9 6h12', 'M9 12h12', 'M9 18h12', 'M4 6h.01', 'M4 12h.01', 'M4 18h.01'],
  timeline: [{ cx: 6, cy: 5, r: 2 }, { cx: 6, cy: 19, r: 2 }, 'M6 7v10', 'M11 5h9', 'M11 19h9', 'M11 12h6'],
  activity: ['M3 12h4l3 8 4-16 3 8h4'],
  alert: ['M12 3.5l9.5 16.5h-19L12 3.5z', 'M12 10v4', 'M12 17h.01'],
  eye: ['M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z', { cx: 12, cy: 12, r: 3 }],
  eyeOff: [
    'M2 12s3.6-7 10-7c2 0 3.7.7 5.1 1.6',
    'M22 12s-3.6 7-10 7c-2 0-3.7-.7-5.1-1.6',
    'M4 4l16 16',
  ],
  check: [sr, 'M8 12.5l2.7 2.7L16 9.5'],
  dismiss: [sr, 'M9 9l6 6', 'M15 9l-6 6'],
  reopen: ['M3 4v6h6', 'M3.5 15a9 9 0 1 0 2.2-9.4L3 10'],
  repeat: [
    'M17 2l4 4-4 4',
    'M3 11V9a3 3 0 0 1 3-3h15',
    'M7 22l-4-4 4-4',
    'M21 13v2a3 3 0 0 1-3 3H3',
  ],
  help: [
    sr,
    'M9.5 9.2a2.5 2.5 0 1 1 3.4 2.4c-.6.3-.9.8-.9 1.4v.5',
    'M12 17h.01',
  ],
  info: [sr, 'M12 11v6', 'M12 7.5h.01'],
  error: ['M8 3h8l5 5v8l-5 5H8l-5-5V8l5-5z', 'M12 8v5', 'M12 16h.01'],
  sun: [
    { cx: 12, cy: 12, r: 4 },
    'M12 2v2',
    'M12 20v2',
    'M4.9 4.9l1.4 1.4',
    'M17.7 17.7l1.4 1.4',
    'M2 12h2',
    'M20 12h2',
    'M4.9 19.1l1.4-1.4',
    'M17.7 6.3l1.4-1.4',
  ],
  moon: ['M20.5 13.2A8.5 8.5 0 1 1 10.8 3.5a6.6 6.6 0 0 0 9.7 9.7z'],
  arrowRight: ['M5 12h14', 'M13 6l6 6-6 6'],
  link: [
    'M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1',
    'M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1',
  ],
  external: ['M14 4h6v6', 'M20 4l-9 9', 'M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5'],
  clock: [sr, 'M12 7v5l3 2'],
  file: ['M14 3H6a1 1 0 0 0-1 1v16a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V8l-5-5z', 'M14 3v5h5'],
  refresh: ['M20 11a8 8 0 1 0-2.3 5.7', 'M20 4v7h-7'],
  sortUp: ['M7 14l5-5 5 5'],
  sortDown: ['M7 10l5 5 5-5'],
  sortNone: ['M8 9l4-4 4 4', 'M8 15l4 4 4-4'],
};

interface IconProps {
  name: string;
  size?: number;
  className?: string;
}

export const Icon: React.FC<IconProps> = ({ name, size = 16, className }) => {
  const def = icons[name] || icons.info;
  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {def.map((item, idx) =>
        typeof item === 'string' ? (
          <path key={idx} d={item} />
        ) : (
          <circle key={idx} cx={item.cx} cy={item.cy} r={item.r} />
        )
      )}
    </svg>
  );
};
