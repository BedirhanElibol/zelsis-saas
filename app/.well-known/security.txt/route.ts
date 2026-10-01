import { CONTACT_EMAIL } from '@/lib/contact';

export async function GET() {
  const content = `Contact: mailto:${CONTACT_EMAIL}
Expires: 2027-12-31T23:59:59.000Z
Preferred-Languages: en, tr`;

  return new Response(content, {
    headers: {
      'Content-Type': 'text/plain',
    },
  });
}
