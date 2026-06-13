import type { Env } from "./index";
import { issueSessionToken } from "./integrity";

const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const ENROLLMENT_CODE_TTL_S = 86400; // 24 hours
const DEVICE_ID_REGEX = /^[A-Za-z0-9._:-]{8,128}$/;
const MAX_PUBLIC_KEY_SPKI_BASE64_LENGTH = 1024;
const MAX_SIGNATURE_BASE64_LENGTH = 1024;

interface EnrollmentCodeRecord {
  device_id: string | null; // null = unbound, string = bound to this device
  created_at: number;
}

interface DeviceEnrollBody {
  device_id?: string;
  public_key_spki?: string;
  enrollment_code?: string;
}

interface DeviceChallengeBody {
  device_id?: string;
}

interface DeviceSessionBody {
  device_id?: string;
  challenge_id?: string;
  signature?: string;
}

interface ActiveChallenge {
  id: string;
  challenge: string;
  expiresAt: number;
}

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function errorResponse(message: string, status: number): Response {
  return jsonResponse({ error: message }, status);
}

function isValidDeviceId(deviceId: string): boolean {
  return DEVICE_ID_REGEX.test(deviceId);
}

function getDeviceAuthStub(env: Env, deviceId: string): DurableObjectStub {
  const durableObjectId = env.DEVICE_AUTH.idFromName(deviceId);
  return env.DEVICE_AUTH.get(durableObjectId);
}

async function constantTimeEquals(left: string, right: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const leftBytes = encoder.encode(left);
  const rightBytes = encoder.encode(right);
  if (leftBytes.byteLength !== rightBytes.byteLength) return false;
  return crypto.subtle.timingSafeEqual(leftBytes, rightBytes);
}

function encodeBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

function decodeBase64(value: string): Uint8Array {
  let normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  while (normalized.length % 4) normalized += "=";
  const decoded = atob(normalized);
  return Uint8Array.from(decoded, (char) => char.charCodeAt(0));
}

async function importDevicePublicKey(publicKeySpki: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "spki",
    decodeBase64(publicKeySpki),
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"]
  );
}

async function verifyChallengeSignature(publicKeySpki: string, challenge: string, signature: string): Promise<boolean> {
  try {
    const publicKey = await importDevicePublicKey(publicKeySpki);
    return await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      decodeBase64(signature),
      decodeBase64(challenge)
    );
  } catch {
    return false;
  }
}

/**
 * POST /v1/device/generate-code — Admin generates a per-device enrollment code.
 *
 * Auth: DEVICE_ENROLLMENT_SECRET acts as the admin bootstrap secret.
 * Body: { admin_secret: string }
 * Response: { code: string, expires_in: number }
 */
export async function handleGenerateCode(request: Request, env: Env): Promise<Response> {
  if (!env.DEVICE_ENROLLMENT_SECRET) {
    return errorResponse("Device enrollment is not configured", 503);
  }

  let body: { admin_secret?: string };
  try {
    body = await request.json() as { admin_secret?: string };
  } catch {
    return errorResponse("Invalid JSON body", 400);
  }

  const adminSecret = body.admin_secret?.trim() ?? "";
  if (!adminSecret || !(await constantTimeEquals(adminSecret, env.DEVICE_ENROLLMENT_SECRET))) {
    return errorResponse("Unauthorized", 403);
  }

  // Generate a 12-char alphanumeric code
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no 0/O/1/I confusion
  const randomBytes = crypto.getRandomValues(new Uint8Array(12));
  const code = Array.from(randomBytes, (b) => chars[b % chars.length]).join("");

  const record: EnrollmentCodeRecord = {
    device_id: null,
    created_at: Date.now(),
  };

  await env.ENROLLMENT_CODES.put(
    `code:${code}`,
    JSON.stringify(record),
    { expirationTtl: ENROLLMENT_CODE_TTL_S }
  );

  return jsonResponse({ code, expires_in: ENROLLMENT_CODE_TTL_S });
}

export async function handleDeviceEnroll(request: Request, env: Env): Promise<Response> {
  if (!env.DEVICE_ENROLLMENT_SECRET) {
    return errorResponse("Device enrollment is not configured", 503);
  }

  let body: DeviceEnrollBody;
  try {
    body = await request.json() as DeviceEnrollBody;
  } catch {
    return errorResponse("Invalid JSON body", 400);
  }

  const deviceId = body.device_id?.trim() ?? "";
  const publicKeySpki = body.public_key_spki?.trim() ?? "";
  const enrollmentCode = body.enrollment_code?.trim() ?? "";

  if (!deviceId || !publicKeySpki || !enrollmentCode) {
    return errorResponse("Missing device_id, public_key_spki, or enrollment_code", 400);
  }
  if (!isValidDeviceId(deviceId)) {
    return errorResponse("Invalid device_id", 400);
  }
  if (publicKeySpki.length > MAX_PUBLIC_KEY_SPKI_BASE64_LENGTH) {
    return errorResponse("Invalid public key", 400);
  }

  // Look up the per-device enrollment code from KV
  const kvKey = `code:${enrollmentCode}`;
  const recordJson = await env.ENROLLMENT_CODES.get(kvKey);

  if (!recordJson) {
    // Fallback: check legacy global secret for backward compatibility during migration
    if (await constantTimeEquals(enrollmentCode, env.DEVICE_ENROLLMENT_SECRET)) {
      // Accept global secret but log a warning — will be removed after migration
      console.log(`legacy_enroll device=${deviceId.substring(0, 8)}... using_global_secret=true`);
    } else {
      return errorResponse("Invalid or expired enrollment code", 403);
    }
  } else {
    const record: EnrollmentCodeRecord = JSON.parse(recordJson);

    if (record.device_id === null) {
      // Code is unbound — bind it to this device
      record.device_id = deviceId;
      await env.ENROLLMENT_CODES.put(kvKey, JSON.stringify(record), { expirationTtl: ENROLLMENT_CODE_TTL_S });
    } else if (record.device_id !== deviceId) {
      // Code already bound to a different device
      return errorResponse("Enrollment code already used by another device", 403);
    }
    // else: same device re-enrolling — allowed (key rotation)
  }

  const stub = getDeviceAuthStub(env, deviceId);
  return stub.fetch("https://device-auth.internal/enroll", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      device_id: deviceId,
      public_key_spki: publicKeySpki,
    }),
  });
}

export async function handleDeviceChallenge(request: Request, env: Env): Promise<Response> {
  let body: DeviceChallengeBody;
  try {
    body = await request.json() as DeviceChallengeBody;
  } catch {
    return errorResponse("Invalid JSON body", 400);
  }

  const deviceId = body.device_id?.trim() ?? "";
  if (!deviceId) {
    return errorResponse("Missing device_id", 400);
  }
  if (!isValidDeviceId(deviceId)) {
    return errorResponse("Invalid device_id", 400);
  }

  const stub = getDeviceAuthStub(env, deviceId);
  return stub.fetch("https://device-auth.internal/challenge", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ device_id: deviceId }),
  });
}

export async function handleDeviceSession(request: Request, env: Env): Promise<Response> {
  let body: DeviceSessionBody;
  try {
    body = await request.json() as DeviceSessionBody;
  } catch {
    return errorResponse("Invalid JSON body", 400);
  }

  const deviceId = body.device_id?.trim() ?? "";
  const challengeId = body.challenge_id?.trim() ?? "";
  const signature = body.signature?.trim() ?? "";

  if (!deviceId || !challengeId || !signature) {
    return errorResponse("Missing device_id, challenge_id, or signature", 400);
  }
  if (!isValidDeviceId(deviceId)) {
    return errorResponse("Invalid device_id", 400);
  }
  if (signature.length > MAX_SIGNATURE_BASE64_LENGTH) {
    return errorResponse("Invalid signature", 400);
  }

  const stub = getDeviceAuthStub(env, deviceId);
  const verificationResponse = await stub.fetch("https://device-auth.internal/session", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      challenge_id: challengeId,
      signature,
    }),
  });

  if (!verificationResponse.ok) {
    return verificationResponse;
  }

  const session = await issueSessionToken(deviceId, env, "device_key");
  return jsonResponse(session);
}

export class DeviceAuthState {
  private static readonly ACTIVE_CHALLENGE_KEY = "activeChallenge";
  private static readonly DEVICE_ID_KEY = "deviceId";
  private static readonly ENROLLED_AT_KEY = "enrolledAt";
  private static readonly PUBLIC_KEY_KEY = "publicKeySpki";

  constructor(
    private readonly ctx: DurableObjectState,
    private readonly env: Env,
  ) {}

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    switch (`${request.method} ${url.pathname}`) {
      case "POST /enroll":
        return this.handleEnroll(request);
      case "POST /challenge":
        return this.handleChallenge(request);
      case "POST /session":
        return this.handleSession(request);
      default:
        return errorResponse("Not found", 404);
    }
  }

  private async handleEnroll(request: Request): Promise<Response> {
    let body: { device_id?: string; public_key_spki?: string };
    try {
      body = await request.json() as { device_id?: string; public_key_spki?: string };
    } catch {
      return errorResponse("Invalid JSON body", 400);
    }

    const deviceId = body.device_id?.trim() ?? "";
    const publicKeySpki = body.public_key_spki?.trim() ?? "";
    if (!deviceId || !publicKeySpki) {
      return errorResponse("Missing device_id or public_key_spki", 400);
    }

    try {
      await importDevicePublicKey(publicKeySpki);
    } catch {
      return errorResponse("Invalid public key", 400);
    }

    await this.ctx.storage.put(DeviceAuthState.DEVICE_ID_KEY, deviceId);
    await this.ctx.storage.put(DeviceAuthState.PUBLIC_KEY_KEY, publicKeySpki);
    await this.ctx.storage.put(DeviceAuthState.ENROLLED_AT_KEY, Date.now());
    await this.ctx.storage.delete(DeviceAuthState.ACTIVE_CHALLENGE_KEY);
    return jsonResponse({ enrolled: true });
  }

  private async handleChallenge(_request: Request): Promise<Response> {
    const publicKeySpki = await this.ctx.storage.get<string>(DeviceAuthState.PUBLIC_KEY_KEY);
    if (!publicKeySpki) {
      return errorResponse("Device not enrolled", 404);
    }

    const challengeBytes = crypto.getRandomValues(new Uint8Array(32));
    const challenge: ActiveChallenge = {
      id: crypto.randomUUID(),
      challenge: encodeBase64(challengeBytes),
      expiresAt: Date.now() + CHALLENGE_TTL_MS,
    };

    await this.ctx.storage.put(DeviceAuthState.ACTIVE_CHALLENGE_KEY, challenge);
    return jsonResponse({
      challenge_id: challenge.id,
      challenge: challenge.challenge,
      expires_at: challenge.expiresAt,
    });
  }

  private async handleSession(request: Request): Promise<Response> {
    let body: { challenge_id?: string; signature?: string };
    try {
      body = await request.json() as { challenge_id?: string; signature?: string };
    } catch {
      return errorResponse("Invalid JSON body", 400);
    }

    const challengeId = body.challenge_id?.trim() ?? "";
    const signature = body.signature?.trim() ?? "";
    if (!challengeId || !signature) {
      return errorResponse("Missing challenge_id or signature", 400);
    }

    const publicKeySpki = await this.ctx.storage.get<string>(DeviceAuthState.PUBLIC_KEY_KEY);
    if (!publicKeySpki) {
      return errorResponse("Device not enrolled", 404);
    }

    const challenge = await this.ctx.storage.get<ActiveChallenge>(DeviceAuthState.ACTIVE_CHALLENGE_KEY);
    if (!challenge || challenge.id != challengeId) {
      return errorResponse("Challenge not found", 404);
    }

    if (Date.now() > challenge.expiresAt) {
      await this.ctx.storage.delete(DeviceAuthState.ACTIVE_CHALLENGE_KEY);
      return errorResponse("Challenge expired", 403);
    }

    const verified = await verifyChallengeSignature(publicKeySpki, challenge.challenge, signature);
    if (!verified) {
      return errorResponse("Invalid signature", 403);
    }

    await this.ctx.storage.delete(DeviceAuthState.ACTIVE_CHALLENGE_KEY);
    return jsonResponse({ verified: true });
  }
}
