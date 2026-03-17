# DS360 Integration Documentation

Technical and dataflow documentation for DS360 (Daiichi Sankyo's Event Cadence deployment) and its connected systems: Cvent, HCP OneLink, Microsoft Exchange, SteepRock SFTP, and SSO.

**Live URL:** https://docs.incadence.com/ds360/integrations

---

## Architecture

```
Your App (Event Cadence)
    │
    │  1. User authenticates → your app issues HS256 JWT
    │  2. User clicks "Open Docs" → redirected to:
    │     https://docs.incadence.com/ds360/integrations?token=<jwt>
    │
    ▼
Cloudflare (docs.incadence.com)
    │
    ├─ /api/auth/verify  →  Cloudflare Worker (validates JWT)
    └─ /*                →  Cloudflare Pages (serves static HTML)
```

---

## Repo Structure

```
ds360-integration-docs/
├── index.html          # Documentation site (single-page)
├── ds360-logo.png      # DS360 brand logo
├── worker/
│   ├── index.js        # Cloudflare Worker — JWT verification + security headers
│   └── wrangler.toml   # Worker deployment config
└── README.md
```

---

## JWT Contract

Tokens are **HS256** JWTs signed with `DS360_JWT_SECRET`.

| Claim | Type | Required | Notes |
|-------|------|----------|-------|
| `sub` | string | Yes | User email address |
| `exp` | Unix timestamp | Yes | Token expiry |
| `role` | string | No | `"viewer"` or `"admin"` — defaults to `"viewer"` |

**Generating a token (Node.js):**
```javascript
const jwt = require('jsonwebtoken');

const token = jwt.sign(
  {
    sub: user.email,
    role: 'viewer',         // or 'admin'
    exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60), // 24h
  },
  process.env.DS360_JWT_SECRET,
  { algorithm: 'HS256' }
);

const docsUrl = `https://docs.incadence.com/ds360/integrations?token=${token}`;
// Redirect user to docsUrl after authentication
```

**Python:**
```python
import jwt, time, os

token = jwt.encode(
    {'sub': user.email, 'role': 'viewer', 'exp': int(time.time()) + 86400},
    os.environ['DS360_JWT_SECRET'],
    algorithm='HS256'
)
docs_url = f'https://docs.incadence.com/ds360/integrations?token={token}'
```

---

## Embedding in an iframe

After your app generates the token URL, embed the docs like this:

```html
<iframe
  src="https://docs.incadence.com/ds360/integrations?token=<jwt>"
  width="100%"
  height="100%"
  style="border: none; min-height: 800px;"
  allow="same-origin"
></iframe>
```

The iframe will display the access denied screen if the token is missing or invalid.

---

## Deployment

### 1. Cloudflare Pages (static site)

1. Go to **Cloudflare Dashboard → Pages → Create a project**
2. Connect this GitHub repo
3. Set build settings:
   - Build command: *(leave blank — no build step)*
   - Build output directory: `/` (root)
4. Set custom domain: `docs.incadence.com`
5. Deploy

### 2. Cloudflare Worker (JWT validator)

```bash
# Install Wrangler CLI
npm install -g wrangler

# Authenticate
wrangler login

# Set the JWT secret (never commit this)
cd worker
wrangler secret put DS360_JWT_SECRET
# Paste your secret when prompted

# Deploy the worker
wrangler deploy
```

The worker automatically routes `docs.incadence.com/*` — intercepting `/api/auth/verify` for JWT validation and adding iframe-friendly security headers to all other responses.

### 3. Cloudflare Route Configuration

In **Cloudflare Dashboard → Workers & Pages → your worker → Triggers**:
- Add route: `docs.incadence.com/*`
- Zone: `incadence.com`

---

## Rotating the Secret

1. Generate a new secret: `openssl rand -hex 32`
2. Update in Cloudflare: `wrangler secret put DS360_JWT_SECRET`
3. Update `DS360_JWT_SECRET` in your Event Cadence app environment
4. No redeployment of the static files needed — the Worker picks up the new secret immediately

---

## Security Notes

- The JWT secret (`DS360_JWT_SECRET`) must **never** be committed to this repo
- The Worker validates the signature server-side — the secret is never exposed to the browser
- Tokens are stored in `sessionStorage` after validation (cleared when tab closes)
- The `frame-ancestors` CSP header restricts embedding to `*.incadence.com` only
