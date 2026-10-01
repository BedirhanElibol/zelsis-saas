import type { Metadata } from 'next';
import { InviteAcceptView } from '@/components/team/InviteAcceptView';

export const metadata: Metadata = {
  title: 'Join a team workspace',
  robots: { index: false, follow: false },
};

export default async function InvitePage({ params }: { params: Promise<{ token: string }> }) {
  const { token } = await params;
  return <InviteAcceptView token={token} />;
}
