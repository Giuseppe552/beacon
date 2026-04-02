export function GET() {
  const body = `Contact: mailto:security@giuseppegiona.com
Expires: 2027-04-02T00:00:00.000Z
Preferred-Languages: en, it
Canonical: https://beacon.giuseppegiona.com/.well-known/security.txt
`;

  return new Response(body, {
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "public, max-age=86400",
    },
  });
}
