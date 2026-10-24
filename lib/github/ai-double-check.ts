import type { SupabaseClient } from '@supabase/supabase-js';
import type { Finding } from '@/data/schema';
import { getEffectivePlanTier } from '@/lib/organization';
import { aiVerifyClient, applyReviews, blockingFindings, localImports, reviewFinding, type AiReview } from '@/lib/ai-verify';

/** True when the user turned the AI double-check on (auth app_metadata, service role only) and has Pro or Team. */
export async function aiVerifyAllowed(admin: SupabaseClient, userId: string): Promise<boolean> {
  const { data } = await admin.auth.admin.getUserById(userId);
  const user = data?.user;
  if (!user || user.app_metadata?.ai_verify !== true) return false;
  const tier = await getEffectivePlanTier(admin, userId, user.email);
  return tier === 'Pro' || tier === 'Enterprise';
}

type ReadFile = (path: string) => Promise<string | null>;

/**
 * Double-check the blocking findings of a pull request with the AI reviewer. Files are read back from GitHub
 * (the scanner has already released them). Any failure leaves the findings unchanged.
 */
export async function aiDoubleCheck(
  findings: Finding[],
  repoPaths: Set<string>,
  readFile: ReadFile,
): Promise<{ findings: Finding[]; reviewed: { finding: Finding; review: AiReview }[] }> {
  const client = aiVerifyClient();
  const targets = blockingFindings(findings);
  if (!client || targets.length === 0) return { findings, reviewed: [] };

  const reviews = new Map<string, AiReview>();
  for (const f of targets) {
    const main = await readFile(f.filePath);
    if (main === null) continue;
    const files = [{ path: f.filePath, content: main }];
    for (const p of localImports(f.filePath, main, (x) => repoPaths.has(x)).slice(0, 2)) {
      const c = await readFile(p);
      if (c !== null) files.push({ path: p, content: c });
    }
    const review = await reviewFinding(client, f, files);
    if (review) reviews.set(f.id, review);
  }
  const updated = applyReviews(findings, reviews);
  return {
    findings: updated,
    reviewed: updated.filter((f) => f.aiReview && reviews.has(f.id)).map((f) => ({ finding: f, review: reviews.get(f.id)! })),
  };
}

/** PR comment section listing what the AI double-check decided. */
export function aiReviewSection(reviewed: { finding: Finding; review: AiReview }[]): string {
  if (reviewed.length === 0) return '';
  const label = { guarded: 'not blocking, guarded', real: 'still blocking', unsure: 'still blocking, not enough context' } as const;
  const rows = reviewed.map(({ finding, review }) => `- \`${finding.filePath}\` ${finding.title}: ${label[review.verdict]}. ${review.reason.replace(/\s+/g, ' ').slice(0, 300)}`);
  return `#### AI double-check (opt-in)\n${rows.join('\n')}\n\n`;
}
