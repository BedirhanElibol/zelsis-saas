import { ImageResponse } from 'next/og';
import { NextRequest } from 'next/server';

export const runtime = 'edge';

export async function GET(req: NextRequest) {
  try {
    const etag = `"${btoa(req.url)}"`;
    if (req.headers.get('if-none-match') === etag) {
      return new Response(null, { status: 304 });
    }

    const { searchParams } = new URL(req.url);

    // Extract params
    const repo = searchParams.get('repo') || 'zelsis/scan';
    const score = searchParams.get('score') || 'N/A';
    const critical = searchParams.get('critical') || '0';
    const high = searchParams.get('high') || '0';
    const medium = searchParams.get('medium') || '0';
    const low = searchParams.get('low') || '0';

    const res = new ImageResponse(
      (
        <div
          style={{
            height: '100%',
            width: '100%',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'flex-start',
            justifyContent: 'center',
            backgroundColor: '#0A0A0A',
            padding: '80px',
            fontFamily: 'sans-serif',
            backgroundImage: 'radial-gradient(circle at 25px 25px, #333 2%, transparent 0%), radial-gradient(circle at 75px 75px, #333 2%, transparent 0%)',
            backgroundSize: '100px 100px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', marginBottom: '40px' }}>
            <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="#10b981" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
            <span style={{ color: '#10b981', fontSize: '32px', fontWeight: 'bold', marginLeft: '16px' }}>Zelsis</span>
          </div>

          <div style={{ color: '#f3f4f6', fontSize: '64px', fontWeight: 'bold', marginBottom: '16px', lineHeight: 1.2 }}>
            Security & Reliability Scan
          </div>

          <div style={{ color: '#9ca3af', fontSize: '32px', marginBottom: '60px' }}>
            {repo}
          </div>

          <div style={{ display: 'flex', width: '100%', justifyContent: 'space-between', alignItems: 'flex-end' }}>
            <div style={{ display: 'flex', gap: '32px' }}>
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', backgroundColor: '#141414', padding: '24px', borderRadius: '16px', border: '1px solid #ef444433' }}>
                <span style={{ color: '#ef4444', fontSize: '48px', fontWeight: 'bold' }}>{critical}</span>
                <span style={{ color: '#9ca3af', fontSize: '20px', marginTop: '8px' }}>CRITICAL</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', backgroundColor: '#141414', padding: '24px', borderRadius: '16px', border: '1px solid #f9731633' }}>
                <span style={{ color: '#f97316', fontSize: '48px', fontWeight: 'bold' }}>{high}</span>
                <span style={{ color: '#9ca3af', fontSize: '20px', marginTop: '8px' }}>HIGH</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', backgroundColor: '#141414', padding: '24px', borderRadius: '16px', border: '1px solid #eab30833' }}>
                <span style={{ color: '#eab308', fontSize: '48px', fontWeight: 'bold' }}>{medium}</span>
                <span style={{ color: '#9ca3af', fontSize: '20px', marginTop: '8px' }}>MEDIUM</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', backgroundColor: '#141414', padding: '24px', borderRadius: '16px', border: '1px solid #3b82f633' }}>
                <span style={{ color: '#3b82f6', fontSize: '48px', fontWeight: 'bold' }}>{low}</span>
                <span style={{ color: '#9ca3af', fontSize: '20px', marginTop: '8px' }}>LOW</span>
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end' }}>
              <span style={{ color: '#9ca3af', fontSize: '24px', marginBottom: '8px' }}>Health Score</span>
              <span style={{ color: score !== 'N/A' && parseInt(score) >= 80 ? '#10b981' : score !== 'N/A' && parseInt(score) >= 60 ? '#eab308' : '#ef4444', fontSize: '80px', fontWeight: 'bold', lineHeight: 1 }}>
                {score}
              </span>
            </div>
          </div>
        </div>
      ),
      {
        width: 1200,
        height: 630,
      }
    );

    res.headers.set('ETag', etag);
    res.headers.set('Cache-Control', 'public, s-maxage=3600, stale-while-revalidate=86400');
    return res;
  } catch (e: any) {
    return new Response(`Failed to generate the image`, {
      status: 500,
    });
  }
}
