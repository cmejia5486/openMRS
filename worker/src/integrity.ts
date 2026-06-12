/**
 * Play Integrity verification + session JWT management.
 *
 * Security model:
 *   - Session JWTs are signed with SESSION_SIGNING_SECRET, a secret that exists
 *     ONLY on the Worker (never shipped in the APK). Even if an attacker extracts
 *     the Android client, they cannot forge session tokens.
 *   - Nonce binding: The client sends sha256(deviceId + ":" + timestamp) as the
 *     integrity nonce. The server recomputes it and verifies it matches the nonce
 *     returned by Google in the verdict, preventing replay and device spoofing.
 *   - Google service account: Uses JSON key to fetch short-lived access tokens
 *     via JWT-based OAuth2 (no manual token rotation needed).
 *
 * Session JWT format (HMAC-SHA256 signed with SESSION_SIGNING_SECRET):
 *   header.payload.signature  (base64url encoded)
 *   payload: { deviceId, iat, exp, authMethod: "integrity" }
 */

import type { Env } from "./index";

const SESSION_TTL_MS = 60 * 60 * 1000; // 1 hour
const PACKAGE_NAME = "com.chartlite.app";

// ── Google Service Account OAuth2 ──

interface ServiceAccountKey {
  client_email: string;
  private_key: string;
  token_uri: string;
}

/** Cached access token so we don't fetch a new one on every request. */
let cachedAccessToken: { token: string; expiresAt: number } | null = null;

/**
 * Get a short-lived Google access token from service account credentials.
 *
 * Uses the standard JWT → token exchange flow:
 *   1. Build a JWT assertion signed with the SA private key
 *   2. POST it to Google's token endpoint
 *   3. Cache the resulting access token until it expires
 */
async function getGoogleAccessToken(env: Env): Promise<string> {
  const now = Math.floor(Date.now() / 1000);

  // Return cached token if still valid (with 60s margin)
  if (cachedAccessToken && now < cachedAccessToken.expiresAt - 60) {
    return cachedAccessToken.token;
  }

  const saKey: ServiceAccountKey = JSON.parse(env.GOOGLE_SERVICE_ACCOUNT_KEY);

  // Build JWT assertion
  const header = { alg: "RS256", typ: "JWT" };
  const payload = {
    iss: saKey.client_email,
    scope: "https://www.googleapis.com/auth/playintegrity",
    aud: saKey.token_uri || "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600, // 1 hour
  };

  const headerB64 = base64UrlEncode(JSON.stringify(header));
  const payloadB64 = base64UrlEncode(JSON.stringify(payload));
  const signingInput = `${headerB64}.${payloadB64}`;

  // Import the RSA private key and sign
  const privateKey = await importPkcs8Key(saKey.private_key);
  const signature = await crypto.subtle.sign(
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    privateKey,
    new TextEncoder().encode(signingInput)
  );
  const signatureB64 = base64UrlEncodeBytes(new Uint8Array(signature));
  const assertion = `${headerB64}.${payloadB64}.${signatureB64}`;

  // Exchange assertion for access token
  const tokenUrl = saKey.token_uri || "https://oauth2.googleapis.com/token";
  const response = await fetch(tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${assertion}`,
  });

  if (!response.ok) {
    const errText = await response.text();
    console.log(`sa_token_error status=${response.status} body=${errText.substring(0, 200)}`);
    throw new Error(`Google OAuth token error: ${response.status}`);
  }

  const result = await response.json() as { access_token: string; expires_in: number };
  cachedAccessToken = {
    token: result.access_token,
    expiresAt: now + (result.expires_in || 3600),
  };
  return result.access_token;
}

/** Import a PEM-encoded PKCS#8 private key for RS256 signing. */
async function importPkcs8Key(pem: string): Promise<CryptoKey> {
  // Strip PEM header/footer and whitespace
  const pemBody = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\s/g, "");
  const binaryStr = atob(pemBody);
  const bytes = new Uint8Array(binaryStr.length);
  for (let i = 0; i < binaryStr.length; i++) {
    bytes[i] = binaryStr.charCodeAt(i);
  }

  return crypto.subtle.importKey(
    "pkcs8",
    bytes.buffer,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );
}

// ── Play Integrity Token Verification ──

interface IntegrityVerdict {
  requestDetails: { requestPackageName: string; nonce: string };
  appIntegrity: { appRecognitionVerdict: string };
  deviceIntegrity: { deviceRecognitionVerdict: string[] };
  accountDetails: { appLicensingVerdict: string };
}

/**
 * Verify a Play Integrity token via Google's API.
 *
 * Checks:
 *   1. Package name matches our app
 *   2. App recognized by Play Store
 *   3. Device meets basic integrity
 *   4. Nonce matches sha256(deviceId + ":" + timestamp) — binds token to request
 */
export async function verifyIntegrityToken(
  integrityToken: string,
  deviceId: string,
  timestamp: number,
  env: Env
): Promise<void> {
  // Get a fresh access token from service account credentials
  const accessToken = await getGoogleAccessToken(env);

  const url = `https://playintegrity.googleapis.com/v1/${PACKAGE_NAME}:decodeIntegrityToken`;

  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${accessToken}`,
    },
    body: JSON.stringify({ integrity_token: integrityToken }),
  });

  if (!response.ok) {
    const errText = await response.text();
    console.log(`integrity_api_error status=${response.status} body=${errText.substring(0, 200)}`);
    throw new Error(`Google Integrity API error: ${response.status}`);
  }

  const result = await response.json() as { tokenPayloadExternal: IntegrityVerdict };
  const verdict = result.tokenPayloadExternal;

  // 1. Verify package name matches our app
  if (verdict.requestDetails.requestPackageName !== PACKAGE_NAME) {
    throw new Error(`Package mismatch: ${verdict.requestDetails.requestPackageName}`);
  }

  // 2. Verify app integrity — must be recognized by Play
  const appVerdict = verdict.appIntegrity.appRecognitionVerdict;
  if (appVerdict !== "PLAY_RECOGNIZED") {
    throw new Error(`App not recognized: ${appVerdict}`);
  }

  // 3. Verify device integrity — must meet basic device integrity
  const deviceVerdicts = verdict.deviceIntegrity.deviceRecognitionVerdict;
  if (!deviceVerdicts.includes("MEETS_DEVICE_INTEGRITY")) {
    throw new Error(`Device integrity failed: ${deviceVerdicts.join(",")}`);
  }

  // 4. Verify nonce binding — proves this token was requested for this device+timestamp
  const expectedNonce = await computeNonce(deviceId, timestamp);
  const actualNonce = verdict.requestDetails.nonce;
  if (actualNonce !== expectedNonce) {
    throw new Error("Nonce mismatch: integrity token not bound to this device/request");
  }

  // 5. Reject stale tokens — timestamp must be within 5 minutes
  const ageMs = Date.now() - timestamp;
  if (ageMs < 0 || ageMs > 5 * 60 * 1000) {
    throw new Error(`Integrity token too old: ${Math.round(ageMs / 1000)}s`);
  }
}

/**
 * Compute the expected nonce: base64url(sha256(deviceId + ":" + timestamp)).
 * Must match the Android client's generateNonce() in PlayIntegrityManager.kt.
 */
async function computeNonce(deviceId: string, timestamp: number): Promise<string> {
  const input = `${deviceId}:${timestamp}`;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return base64UrlEncodeBytes(new Uint8Array(digest));
}

// ── Session JWT (signed with SESSION_SIGNING_SECRET, never in APK) ──

interface SessionPayload {
  deviceId: string;
  iat: number;  // Issued at (epoch ms)
  exp: number;  // Expires at (epoch ms)
  authMethod: "integrity" | "device_key";
}

/**
 * Issue a session JWT signed with SESSION_SIGNING_SECRET (server-only key).
 */
export async function issueSessionToken(
  deviceId: string,
  env: Env,
  authMethod: SessionPayload["authMethod"] = "integrity"
): Promise<{ session_token: string; expires_at: number }> {
  const now = Date.now();
  const expiresAt = now + SESSION_TTL_MS;

  const payload: SessionPayload = {
    deviceId,
    iat: now,
    exp: expiresAt,
    authMethod,
  };

  const token = await signJwt(payload, env);
  return { session_token: token, expires_at: expiresAt };
}

/**
 * Verify a session JWT. Returns the payload if valid, null if expired/invalid.
 */
export async function verifySessionToken(
  token: string,
  env: Env
): Promise<SessionPayload | null> {
  const parts = token.split(".");
  if (parts.length !== 3) return null;

  const [headerB64, payloadB64, signatureB64] = parts;

  // Verify signature using SESSION_SIGNING_SECRET (constant-time comparison)
  const signingInput = `${headerB64}.${payloadB64}`;
  const expectedSig = await hmacSign(signingInput, env);
  const enc = new TextEncoder();
  const expectedBuf = enc.encode(expectedSig);
  const signatureBuf = enc.encode(signatureB64);
  if (expectedBuf.byteLength !== signatureBuf.byteLength) return null;
  if (!crypto.subtle.timingSafeEqual(expectedBuf, signatureBuf)) return null;

  // Decode payload
  try {
    const payloadJson = atob(base64UrlToBase64(payloadB64));
    const payload = JSON.parse(payloadJson) as SessionPayload;

    // Check expiry
    if (Date.now() > payload.exp) return null;

    return payload;
  } catch {
    return null;
  }
}

// ── JWT Helpers ──

async function signJwt(payload: SessionPayload, env: Env): Promise<string> {
  const header = { alg: "HS256", typ: "JWT" };
  const headerB64 = base64UrlEncode(JSON.stringify(header));
  const payloadB64 = base64UrlEncode(JSON.stringify(payload));
  const signingInput = `${headerB64}.${payloadB64}`;
  const signature = await hmacSign(signingInput, env);
  return `${headerB64}.${payloadB64}.${signature}`;
}

/** HMAC-SHA256 using SESSION_SIGNING_SECRET (server-only, never in APK). */
async function hmacSign(input: string, env: Env): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(env.SESSION_SIGNING_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(input));
  return base64UrlEncodeBytes(new Uint8Array(sig));
}

function base64UrlEncode(str: string): string {
  return btoa(str)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64UrlEncodeBytes(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64UrlToBase64(str: string): string {
  let result = str.replace(/-/g, "+").replace(/_/g, "/");
  while (result.length % 4) result += "=";
  return result;
}
