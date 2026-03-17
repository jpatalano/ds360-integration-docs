/**
 * DS360 Integration Docs — Cloudflare Worker
 * 
 * Handles:
 *   POST /api/auth/verify  — validates HS256 JWT, returns { valid, sub, role }
 *   GET  /*                — serves static files from Pages with iframe-friendly headers
 * 
 * Environment variables (set in Cloudflare dashboard):
 *   MSD_JWT_SECRET  — shared secret used to sign JWTs (HS256)
 */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // ── JWT Verification Endpoint ────────────────────────────────────────
    if (request.method === 'POST' && url.pathname === '/api/auth/verify') {
      return handleVerify(request, env);
    }

    // ── Static file passthrough with security headers ────────────────────
    const response = await fetch(request);
    return addSecurityHeaders(response);
  }
};

// ── JWT Verify Handler ───────────────────────────────────────────────────
async function handleVerify(request, env) {
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Type': 'application/json',
  };

  // Handle CORS preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  try {
    const body = await request.json();
    const token = body?.token;

    if (!token || typeof token !== 'string') {
      return new Response(JSON.stringify({ valid: false, error: 'missing_token' }), {
        status: 400, headers: corsHeaders
      });
    }

    const secret = env.MSD_JWT_SECRET;
    if (!secret) {
      console.error('MSD_JWT_SECRET environment variable is not set');
      return new Response(JSON.stringify({ valid: false, error: 'server_config_error' }), {
        status: 500, headers: corsHeaders
      });
    }

    // Decode and verify the JWT
    const result = await verifyJWT(token, secret);

    if (!result.valid) {
      return new Response(JSON.stringify({ valid: false, error: result.error }), {
        status: 401, headers: corsHeaders
      });
    }

    return new Response(JSON.stringify({
      valid: true,
      sub: result.payload.sub,
      role: result.payload.role || 'viewer',
    }), { status: 200, headers: corsHeaders });

  } catch (err) {
    return new Response(JSON.stringify({ valid: false, error: 'internal_error' }), {
      status: 500, headers: corsHeaders
    });
  }
}

// ── HS256 JWT Verification ───────────────────────────────────────────────
async function verifyJWT(token, secret) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return { valid: false, error: 'malformed_token' };

    const [headerB64, payloadB64, sigB64] = parts;

    // Decode header and verify algorithm
    const header = JSON.parse(base64UrlDecode(headerB64));
    if (header.alg !== 'HS256') return { valid: false, error: 'wrong_algorithm' };

    // Import the secret key
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw', enc.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false, ['verify']
    );

    // Verify signature
    const signingInput = `${headerB64}.${payloadB64}`;
    const sigBytes = base64UrlToBytes(sigB64);
    const valid = await crypto.subtle.verify(
      'HMAC', key,
      sigBytes,
      enc.encode(signingInput)
    );

    if (!valid) return { valid: false, error: 'invalid_signature' };

    // Decode payload
    const payload = JSON.parse(base64UrlDecode(payloadB64));

    // Check required claims
    if (!payload.sub) return { valid: false, error: 'missing_sub' };
    if (!payload.exp) return { valid: false, error: 'missing_exp' };

    // Check expiry
    const now = Math.floor(Date.now() / 1000);
    if (now > payload.exp) return { valid: false, error: 'token_expired' };

    // Validate role if present
    if (payload.role && !['viewer', 'admin'].includes(payload.role)) {
      return { valid: false, error: 'invalid_role' };
    }

    return { valid: true, payload };

  } catch (err) {
    return { valid: false, error: 'decode_error' };
  }
}

// ── Security Headers (iframe-friendly) ──────────────────────────────────
function addSecurityHeaders(response) {
  const newHeaders = new Headers(response.headers);

  // Allow embedding in iframes from same origin + your app domain
  // Update frame-ancestors to match your app's domain
  newHeaders.set('Content-Security-Policy',
    "frame-ancestors 'self' https://*.incadence.com https://incadence.com"
  );

  // Do NOT set X-Frame-Options — it conflicts with CSP frame-ancestors
  // and is less flexible. CSP is the modern standard.
  newHeaders.delete('X-Frame-Options');

  // Other security headers
  newHeaders.set('X-Content-Type-Options', 'nosniff');
  newHeaders.set('Referrer-Policy', 'strict-origin-when-cross-origin');

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: newHeaders,
  });
}

// ── Base64url Helpers ────────────────────────────────────────────────────
function base64UrlDecode(str) {
  // Convert base64url to base64
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  // Pad to multiple of 4
  while (str.length % 4) str += '=';
  return atob(str);
}

function base64UrlToBytes(str) {
  const decoded = base64UrlDecode(str);
  return Uint8Array.from(decoded, c => c.charCodeAt(0));
}
