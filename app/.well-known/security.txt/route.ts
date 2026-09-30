export async function GET() {
  const content = `Contact: security@zelsis.com
Expires: 2027-12-31T23:59:59.000Z
Acknowledgments: https://zelsis.com/hall-of-fame
Preferred-Languages: en, tr`;

  return new Response(content, {
    headers: {
      'Content-Type': 'text/plain',
    },
  });
}
