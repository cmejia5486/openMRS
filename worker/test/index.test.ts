/**
 * Worker integration tests.
 *
 * Tests the auth layer, rate limiting, routing, and session exchange logic
 * using the Cloudflare Workers Vitest pool (runs in a real miniflare runtime).
 *
 * External upstream calls (Google Integrity API, STT, Claude, etc.) are NOT
 * tested here — they'd need mock servers or separate integration tests.
 * These tests focus on the Worker's own logic: auth, routing, and enrollment.
 */

import { describe, it, expect } from "vitest";
import { SELF, env } from "cloudflare:test";

// ── Helpers ──

/** Generate a valid session JWT using SESSION_SIGNING_SECRET. */
async function issueTestSessionJwt(
  deviceId: string,
  signingSecret: string,
  overrides?: { authMethod?: "integrity" | "device_key"; exp?: number; iat?: number }
): Promise<string> {
  const now = Date.now();
  const header = { alg: "HS256", typ: "JWT" };
  const payload = {
    deviceId,
    iat: overrides?.iat ?? now,
    exp: overrides?.exp ?? now + 3600_000,
    authMethod: overrides?.authMethod ?? "integrity",
  };

  const headerB64 = base64UrlEncode(JSON.stringify(header));
  const payloadB64 = base64UrlEncode(JSON.stringify(payload));
  const signingInput = `${headerB64}.${payloadB64}`;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(signingSecret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(signingInput));
  const signatureB64 = base64UrlEncodeBytes(new Uint8Array(sig));
  return `${headerB64}.${payloadB64}.${signatureB64}`;
}

async function generateDeviceKeyPair(): Promise<{ privateKey: CryptoKey; publicKeySpki: string }> {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
  const spki = await crypto.subtle.exportKey("spki", keyPair.publicKey);
  return {
    privateKey: keyPair.privateKey,
    publicKeySpki: base64EncodeBytes(new Uint8Array(spki)),
  };
}

async function signChallenge(privateKey: CryptoKey, challengeBase64: string): Promise<string> {
  const challengeBytes = base64Decode(challengeBase64);
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    challengeBytes
  );
  return base64EncodeBytes(new Uint8Array(signature));
}

function base64UrlEncode(str: string): string {
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlEncodeBytes(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64EncodeBytes(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

function base64Decode(value: string): Uint8Array {
  let normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  while (normalized.length % 4) normalized += "=";
  const decoded = atob(normalized);
  return Uint8Array.from(decoded, (char) => char.charCodeAt(0));
}

// ── Tests ──

describe("Health endpoint", () => {
  it("returns 200 with status ok", async () => {
    const res = await SELF.fetch("https://api.chartlite.health/v1/health");
    expect(res.status).toBe(200);
    const body = await res.json() as { status: string };
    expect(body.status).toBe("ok");
  });
});

describe("Auth: unauthenticated requests", () => {
  it("rejects requests with no auth headers", async () => {
    const res = await SELF.fetch("https://api.chartlite.health/v1/transcribe", {
      method: "POST",
      body: "{}",
    });
    expect(res.status).toBe(401);
  });

  it("rejects legacy HMAC fallback headers", async () => {
    const res = await SELF.fetch("https://api.chartlite.health/v1/transcribe", {
      method: "POST",
      headers: { "X-ChartLite-Token": "legacy-device:legacy-token" },
      body: "{}",
    });
    expect(res.status).toBe(401);
  });
});

describe("Auth: Session JWT", () => {
  it("accepts a valid session JWT signed with SESSION_SIGNING_SECRET", async () => {
    const jwt = await issueTestSessionJwt("test-device-002", env.SESSION_SIGNING_SECRET);
    const res = await SELF.fetch("https://api.chartlite.health/v1/transcribe", {
      method: "POST",
      headers: {
        "X-Session-Token": jwt,
        "X-ChartLite-Provider": "google_cloud",
        "Content-Type": "application/json",
      },
      body: "{}",
    });
    expect(res.status).not.toBe(401);
  });

  it("rejects a JWT signed with the enrollment code", async () => {
    const jwt = await issueTestSessionJwt("test-device-003", env.DEVICE_ENROLLMENT_SECRET);
    const res = await SELF.fetch("https://api.chartlite.health/v1/transcribe", {
      method: "POST",
      headers: {
        "X-Session-Token": jwt,
        "Content-Type": "application/json",
      },
      body: "{}",
    });
    expect(res.status).toBe(401);
  });

  it("rejects an expired session JWT", async () => {
    const jwt = await issueTestSessionJwt("test-device-004", env.SESSION_SIGNING_SECRET, {
      iat: Date.now() - 7200_000,
      exp: Date.now() - 3600_000,
    });
    const res = await SELF.fetch("https://api.chartlite.health/v1/transcribe", {
      method: "POST",
      headers: {
        "X-Session-Token": jwt,
        "Content-Type": "application/json",
      },
      body: "{}",
    });
    expect(res.status).toBe(401);
  });
});

describe("Session exchange endpoint", () => {
  it("rejects requests missing required fields", async () => {
    const res = await SELF.fetch("https://api.chartlite.health/v1/auth/session", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ device_id: "test" }),
    });
    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toContain("Missing");
  });

  it("rejects requests with invalid timestamp", async () => {
    const res = await SELF.fetch("https://api.chartlite.health/v1/auth/session", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        integrity_token: "fake-token",
        device_id: "test-device",
        timestamp: -1,
      }),
    });
    expect(res.status).toBe(400);
  });

  it("rejects requests with non-JSON body", async () => {
    const res = await SELF.fetch("https://api.chartlite.health/v1/auth/session", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "not json",
    });
    expect(res.status).toBe(400);
  });
});

describe("Device enrollment flow", () => {
  it("rejects enrollment requests missing required fields", async () => {
    const res = await SELF.fetch("https://api.chartlite.health/v1/auth/device/enroll", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ device_id: "test-device-010" }),
    });
    expect(res.status).toBe(400);
  });

  it("rejects invalid enrollment codes", async () => {
    const { publicKeySpki } = await generateDeviceKeyPair();
    const res = await SELF.fetch("https://api.chartlite.health/v1/auth/device/enroll", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        device_id: "test-device-011",
        public_key_spki: publicKeySpki,
        enrollment_code: "wrong-code",
      }),
    });
    expect(res.status).toBe(403);
  });

  it("enrolls a device, issues a challenge, and exchanges it for a session", async () => {
    const deviceId = "test-device-012";
    const { privateKey, publicKeySpki } = await generateDeviceKeyPair();

    const enrollRes = await SELF.fetch("https://api.chartlite.health/v1/auth/device/enroll", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        device_id: deviceId,
        public_key_spki: publicKeySpki,
        enrollment_code: env.DEVICE_ENROLLMENT_SECRET,
      }),
    });
    expect(enrollRes.status).toBe(200);

    const challengeRes = await SELF.fetch("https://api.chartlite.health/v1/auth/device/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ device_id: deviceId }),
    });
    expect(challengeRes.status).toBe(200);
    const challengeBody = await challengeRes.json() as {
      challenge_id: string;
      challenge: string;
    };

    const signature = await signChallenge(privateKey, challengeBody.challenge);
    const sessionRes = await SELF.fetch("https://api.chartlite.health/v1/auth/device/session", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        device_id: deviceId,
        challenge_id: challengeBody.challenge_id,
        signature,
      }),
    });
    expect(sessionRes.status).toBe(200);
    const sessionBody = await sessionRes.json() as { session_token: string };
    expect(sessionBody.session_token).toBeTruthy();

    const proxiedRes = await SELF.fetch("https://api.chartlite.health/v1/transcribe", {
      method: "POST",
      headers: {
        "X-Session-Token": sessionBody.session_token,
        "X-ChartLite-Provider": "google_cloud",
        "Content-Type": "application/json",
      },
      body: "{}",
    });
    expect(proxiedRes.status).not.toBe(401);
  });

  it("rejects challenge requests for unknown devices", async () => {
    const res = await SELF.fetch("https://api.chartlite.health/v1/auth/device/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ device_id: "test-device-013" }),
    });
    expect(res.status).toBe(404);
  });

  it("rejects malformed device signatures", async () => {
    const deviceId = "test-device-014";
    const { publicKeySpki } = await generateDeviceKeyPair();

    await SELF.fetch("https://api.chartlite.health/v1/auth/device/enroll", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        device_id: deviceId,
        public_key_spki: publicKeySpki,
        enrollment_code: env.DEVICE_ENROLLMENT_SECRET,
      }),
    });

    const challengeRes = await SELF.fetch("https://api.chartlite.health/v1/auth/device/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ device_id: deviceId }),
    });
    const challengeBody = await challengeRes.json() as { challenge_id: string };

    const sessionRes = await SELF.fetch("https://api.chartlite.health/v1/auth/device/session", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        device_id: deviceId,
        challenge_id: challengeBody.challenge_id,
        signature: base64EncodeBytes(new Uint8Array([1, 2, 3, 4])),
      }),
    });
    expect(sessionRes.status).toBe(400);
  });
});

describe("Routing", () => {
  it("returns 404 for unknown paths", async () => {
    const jwt = await issueTestSessionJwt("test-device-006", env.SESSION_SIGNING_SECRET);
    const res = await SELF.fetch("https://api.chartlite.health/v1/unknown", {
      method: "POST",
      headers: { "X-Session-Token": jwt },
    });
    expect(res.status).toBe(404);
  });

  it("returns 204 for OPTIONS (CORS preflight)", async () => {
    const res = await SELF.fetch("https://api.chartlite.health/v1/transcribe", {
      method: "OPTIONS",
    });
    expect(res.status).toBe(204);
  });

  it("rejects unknown transcription provider", async () => {
    const jwt = await issueTestSessionJwt("test-device-007", env.SESSION_SIGNING_SECRET);
    const res = await SELF.fetch("https://api.chartlite.health/v1/transcribe", {
      method: "POST",
      headers: {
        "X-Session-Token": jwt,
        "X-ChartLite-Provider": "nonexistent_provider",
        "Content-Type": "application/json",
      },
      body: "{}",
    });
    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toContain("Unknown provider");
  });
});

describe("Claude proxy validation", () => {
  it("rejects disallowed model names", async () => {
    const jwt = await issueTestSessionJwt("test-device-008", env.SESSION_SIGNING_SECRET);
    const res = await SELF.fetch("https://api.chartlite.health/v1/extract", {
      method: "POST",
      headers: {
        "X-Session-Token": jwt,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ model: "gpt-4", max_tokens: 100, messages: [] }),
    });
    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toContain("Model not allowed");
  });
});

describe("Body size limits", () => {
  it("rejects oversized Claude extraction requests", async () => {
    const jwt = await issueTestSessionJwt("test-device-009", env.SESSION_SIGNING_SECRET);
    const bigBody = "x".repeat(2_000_000);
    const res = await SELF.fetch("https://api.chartlite.health/v1/extract", {
      method: "POST",
      headers: {
        "X-Session-Token": jwt,
        "Content-Type": "application/json",
        "Content-Length": String(bigBody.length),
      },
      body: bigBody,
    });
    expect(res.status).toBe(413);
  });
});
