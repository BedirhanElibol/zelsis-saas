import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [8844],
    name: 'PY-SEC-44 unverified JWT decode for identity vs peek-to-route followed by verification',
    detects: [
      ...f(
        'app/routers/sso.py',
        `import jwt

async def handle_sso_callback(request, access_token):
    # Decode token to get user info (no verification)
    payload = jwt.decode(access_token, options={"verify_signature": False})
    user_email = payload.get("email")
    is_admin = payload.get("user", {}).get("is_admin", False)
    return {"email": user_email, "is_admin": is_admin}
`
      ),
      ...f(
        'app/auth/identity.py',
        `import jwt

def get_current_user(token):
    unverified = jwt.decode(token, options={"verify_signature": False})
    return unverified["sub"]
`
      ),
    ],
    ignores: [
      ...f(
        'app/transports/transport.py',
        `import jwt

async def route_token(token):
    unverified = jwt.decode(token, options={"verify_signature": False})
    if unverified.get("iss") == "internal":
        return None
    claims = await verify_oauth_access_token(token)
    return claims.get("email")
`
      ),
      ...f(
        'app/auth/jwks_verify.py',
        `import jwt

def decode_with_jwks(token):
    header = jwt.get_unverified_header(token)
    kid = header.get("kid")
    key = get_key(kid)
    return jwt.decode(token, key=key, algorithms=["RS256"])
`
      ),
      ...f(
        'knowledge/frameworks/fastapi.py',
        `import jwt

def example_doc(token):
    return jwt.decode(token, options={"verify_signature": False})
`
      ),
    ],
  },
];
