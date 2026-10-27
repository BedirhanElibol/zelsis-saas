import { ImageResponse } from 'next/og';

export const alt = 'Zelsis | Release Checks for Web, Mobile and SaaS Apps';
export const size = { width: 1200, height: 630 };
export const contentType = 'image/png';

const CHECKS = ['Logic bugs', 'Security', 'Dependencies', 'UI & accessibility', 'Privacy', 'Infra & CI config'];
const STACKS = 'JavaScript · Python · Go · Ruby · PHP · Java · C# · Swift · Kotlin';

/** Social preview card. Text only, so it never drifts from the product the way a screenshot does. */
export default function OpengraphImage() {
  return new ImageResponse(
    (
      <div style={{ width: '100%', height: '100%', display: 'flex', flexDirection: 'column', justifyContent: 'space-between', padding: '64px 72px', background: '#0A0A0A', color: '#EDEDED', fontFamily: 'sans-serif' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <div style={{ width: 56, height: 56, borderRadius: 12, background: '#111', border: '2px solid #10B981', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 34, fontWeight: 800, color: '#10B981' }}>Z</div>
          <div style={{ display: 'flex', fontSize: 36, fontWeight: 800 }}>Zelsis</div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          <div style={{ display: 'flex', fontSize: 60, fontWeight: 800, lineHeight: 1.1, letterSpacing: -1 }}>Catch the bug that costs you customers, before you merge.</div>
          <div style={{ display: 'flex', fontSize: 28, color: '#A1A1AA' }}>Zelsis catches it before it merges. Try it on your repo free.</div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12 }}>
            {CHECKS.map((c) => (
              <div key={c} style={{ display: 'flex', padding: '8px 16px', borderRadius: 999, border: '1px solid #10B98155', color: '#34D399', fontSize: 22 }}>{c}</div>
            ))}
          </div>
          <div style={{ display: 'flex', fontSize: 22, color: '#71717A' }}>{`${STACKS} · zelsis.com`}</div>
        </div>
      </div>
    ),
    size
  );
}
