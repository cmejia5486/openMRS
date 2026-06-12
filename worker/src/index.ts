/**
 * ChartLite API Proxy — Cloudflare Worker
 *
 * Routes cloud ASR and Claude extraction calls through ChartLite's backend,
 * keeping all provider API keys server-side. Two session-issuance paths:
 *
 *   1. Play Integrity session (preferred): App obtains a Play Integrity token
 *      from Google, exchanges it via POST /v1/auth/session for a 1-hour JWT.
 *      The JWT is signed with SESSION_SIGNING_SECRET (server-only, never in APK).
 *      Nonce binding: client sends sha256(deviceId + ":" + timestamp) as nonce,
 *      server recomputes and verifies against the verdict — prevents replay/spoofing.
 *
 *   2. Device-key session (non-GMS): App generates a non-exportable Android
 *      Keystore key, enrolls its public key with a one-time enrollment code,
 *      then proves possession via challenge-response to mint the same JWT type.
 *
 * Endpoints:
 *   POST /v1/auth/session         — Exchange Play Integrity token for session JWT
 *   POST /v1/device/generate-code  — Admin: generate a per-device enrollment code
 *   POST /v1/auth/device/enroll   — Enroll a non-GMS device public key (per-device code)
 *   POST /v1/auth/device/challenge — Issue a device-signing challenge
 *   POST /v1/auth/device/session  — Exchange signed challenge for session JWT
 *   POST /v1/transcribe           — Proxy audio to Gemini / Deepgram / OpenAI
 *   POST /v1/extract              — Proxy transcript to Claude for clinical extraction
 *   POST /v1/generate-note        — Proxy transcript to Claude for note generation
 *   GET  /v1/health               — Health check
 *
 * Deploy:
 *   cd worker && npx wrangler deploy
 *   npx wrangler secret put DEVICE_ENROLLMENT_SECRET
 *   npx wrangler secret put SESSION_SIGNING_SECRET
 *   npx wrangler secret put GOOGLE_SERVICE_ACCOUNT_KEY
 *   npx wrangler secret put GEMINI_API_KEY
 *   npx wrangler secret put DEEPGRAM_API_KEY
 *   npx wrangler secret put OPENAI_API_KEY
 *   npx wrangler secret put ANTHROPIC_API_KEY
 */

import {
  DeviceAuthState,
  handleDeviceChallenge,
  handleDeviceEnroll,
  handleDeviceSession,
  handleGenerateCode,
} from "./device-auth";
import { verifyIntegrityToken, issueSessionToken, verifySessionToken } from "./integrity";

export { DeviceAuthState };

export interface Env {
  DEVICE_AUTH: DurableObjectNamespace;
  ENROLLMENT_CODES: KVNamespace;
  DEVICE_ENROLLMENT_SECRET: string; // Now used as admin secret for generating per-device codes
  SESSION_SIGNING_SECRET: string; // JWT signing key (server-only — NEVER in APK)
  GOOGLE_SERVICE_ACCOUNT_KEY: string; // Google SA JSON key for Play Integrity (auto-refreshes tokens)
  GEMINI_API_KEY: string;       // Gemini API key for cloud ASR transcription
  DEEPGRAM_API_KEY: string;
  OPENAI_API_KEY: string;
  ANTHROPIC_API_KEY: string;
  ENVIRONMENT: string;
}

// ── Constants ──

const MAX_AUDIO_BODY_BYTES = 26_214_400;  // 25 MB (OpenAI limit + margin)
const MAX_GEMINI_BODY_BYTES = 20_971_520; // 20 MB (Gemini inline audio limit)
const MAX_CLAUDE_BODY_BYTES = 1_048_576;  // 1 MB (extraction requests)
const ALLOWED_CLAUDE_MODELS = new Set([
  "claude-sonnet-4-20250514", "claude-haiku-4-20250514",
  "claude-sonnet-4-6", "claude-opus-4-6",
]);
const MAX_CLAUDE_TOKENS = 4096;
const ALLOWED_EXTRACT_PROVIDERS = new Set(["claude", "gemini", "openai"]);
const ALLOWED_OPENAI_EXTRACT_MODELS = new Set(["gpt-5.4", "gpt-4.1", "gpt-5.4-mini"]);
const ALLOWED_GEMINI_EXTRACT_MODELS = new Set(["gemini-3.1-flash-lite-preview"]);
const ALLOWED_DEEPGRAM_PARAMS = new Set([
  "model", "language", "punctuate", "smart_format", "sample_rate",
  "diarize", "utterances", "keywords",
]);
const ALLOWED_PROVIDERS = new Set(["gemini", "deepgram", "openai"]);

// Gemini 3.1 Flash Lite Preview — latest, fast, strong multilingual audio support
// See: https://ai.google.dev/gemini-api/docs/models/gemini-3.1-flash-lite-preview
const GEMINI_MODEL = "gemini-3.1-flash-lite-preview";

// ── Auth ──

interface AuthResult {
  authorized: boolean;
  deviceId: string;
  authMethod: "integrity" | "device_key" | "none";
}

/**
 * Authenticate the request via a signed session JWT.
 *
 * Both Play Integrity and non-GMS device-key enrollment mint the same session
 * token format. No client-embedded shared secret is accepted here.
 */
async function authenticate(request: Request, env: Env): Promise<AuthResult> {
  const sessionToken = request.headers.get("X-Session-Token");
  if (sessionToken) {
    const payload = await verifySessionToken(sessionToken, env);
    if (payload) {
      return { authorized: true, deviceId: payload.deviceId, authMethod: payload.authMethod };
    }
    return { authorized: false, deviceId: "", authMethod: "none" };
  }
  return { authorized: false, deviceId: "", authMethod: "none" };
}

// ── Session Exchange ──

/**
 * POST /v1/auth/session — Exchange a Play Integrity token for a session JWT.
 *
 * Body: { integrity_token: string, device_id: string, timestamp: number }
 *
 * The client computes nonce = base64url(sha256(device_id + ":" + timestamp))
 * and includes it in the Play Integrity request. The server recomputes the nonce
 * from the posted device_id + timestamp and verifies it matches the verdict,
 * binding the token to this specific device and moment.
 *
 * Response: { session_token: string, expires_at: number }
 */
async function handleSessionExchange(request: Request, env: Env): Promise<Response> {
  let body: { integrity_token?: string; device_id?: string; timestamp?: number };
  try {
    body = await request.json() as { integrity_token?: string; device_id?: string; timestamp?: number };
  } catch {
    return errorResponse("Invalid JSON body", 400);
  }

  const { integrity_token, device_id, timestamp } = body;
  if (!integrity_token || !device_id || !timestamp) {
    return errorResponse("Missing integrity_token, device_id, or timestamp", 400);
  }

  if (typeof timestamp !== "number" || timestamp <= 0) {
    return errorResponse("Invalid timestamp", 400);
  }

  try {
    // Verify with Google's Play Integrity API (includes nonce + staleness checks)
    await verifyIntegrityToken(integrity_token, device_id, timestamp, env);

    // Issue a session JWT signed with SESSION_SIGNING_SECRET (server-only key)
    const session = await issueSessionToken(device_id, env);
    console.log(`session_issued device=${device_id.substring(0, 8)}...`);
    return jsonResponse(session);
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : "Attestation failed";
    console.log(`integrity_rejected device=${device_id.substring(0, 8)}... reason=${message}`);
    return errorResponse("Attestation failed", 403);
  }
}

// ── Rate Limiting ──
//
// Three layers, differentiated by auth trust level:
//   1. Per-IP: abuse barrier — constrains even attackers who rotate device IDs.
//   2. Per-device: catches runaway loops from legitimate clients.
//   3. Auth-method multiplier: manually enrolled device-key clients (lower
//      trust) get tighter quotas than integrity-attested clients.
//
// Both are in-memory per-isolate (resets on cold start). Cloudflare Workers
// spread traffic across isolates, so effective limits are slightly higher
// than configured — acceptable for cost-protection purposes.
//
// Play Integrity attestation is the highest-trust path.
// Device-key enrollment remains rate-limited more tightly.

const IP_RATE_WINDOW_MS = 60_000;       // 1-minute window
const IP_RATE_MAX_REQUESTS = 60;        // 60 req/min per IP (generous for clinics sharing NAT)
const DEVICE_RATE_WINDOW_MS = 60_000;

// Per-device quotas differentiated by trust level:
//   - integrity: 30 req/min — attested genuine app on real device
//   - device_key: 10 req/min — manually enrolled device, lower trust
const DEVICE_RATE_INTEGRITY = 30;
const DEVICE_RATE_DEVICE_KEY = 10;

interface RateBucket {
  count: number;
  resetAt: number;
}

const ipRateLimits = new Map<string, RateBucket>();
const deviceRateLimits = new Map<string, RateBucket>();

function checkRateLimit(key: string, map: Map<string, RateBucket>, windowMs: number, maxRequests: number): boolean {
  const now = Date.now();
  const bucket = map.get(key);

  if (!bucket || now >= bucket.resetAt) {
    map.set(key, { count: 1, resetAt: now + windowMs });
    return false;
  }

  bucket.count++;
  return bucket.count > maxRequests;
}

/** Get client IP from CF-Connecting-IP (set by Cloudflare edge) */
function getClientIp(request: Request): string {
  return request.headers.get("CF-Connecting-IP") || "unknown";
}

function cleanupRateLimits(): void {
  const now = Date.now();
  for (const [key, bucket] of ipRateLimits) {
    if (now >= bucket.resetAt) ipRateLimits.delete(key);
  }
  for (const [key, bucket] of deviceRateLimits) {
    if (now >= bucket.resetAt) deviceRateLimits.delete(key);
  }
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

// ── Body size check ──

function checkContentLength(request: Request, maxBytes: number): string | null {
  const cl = request.headers.get("Content-Length");
  if (cl && parseInt(cl, 10) > maxBytes) {
    return `Request body too large (max ${Math.round(maxBytes / 1_048_576)}MB)`;
  }
  return null;
}

// ── Transcription Proxy ──

async function handleTranscribe(request: Request, env: Env): Promise<Response> {
  const provider = request.headers.get("X-ChartLite-Provider") || "gemini";

  if (!ALLOWED_PROVIDERS.has(provider)) {
    return errorResponse(`Unknown provider: ${provider}`, 400);
  }

  const startMs = Date.now();

  let response: Response;
  switch (provider) {
    case "gemini":
      response = await proxyGemini(request, env);
      break;
    case "deepgram":
      response = await proxyDeepgram(request, env);
      break;
    case "openai":
      response = await proxyOpenAI(request, env);
      break;
    default:
      return errorResponse(`Unknown provider: ${provider}`, 400);
  }

  console.log(`transcribe provider=${provider} status=${response.status} latency=${Date.now() - startMs}ms`);
  return response;
}

/**
 * Proxy audio to Gemini 2.5 Flash Preview for transcription.
 *
 * Expects JSON body: { audio_data: string (base64), mime_type: string, language: string }
 * Returns JSON: { transcript: string }
 *
 * Gemini's multimodal understanding provides strong African language support
 * (Swahili, Amharic, Zulu, Xhosa, etc.) without a separate STT API key.
 */
async function proxyGemini(request: Request, env: Env): Promise<Response> {
  const sizeErr = checkContentLength(request, MAX_GEMINI_BODY_BYTES);
  if (sizeErr) return errorResponse(sizeErr, 413);

  const rawBody = await request.text();
  if (new TextEncoder().encode(rawBody).byteLength > MAX_GEMINI_BODY_BYTES) {
    return errorResponse(`Request body too large (max ${Math.round(MAX_GEMINI_BODY_BYTES / 1_048_576)}MB)`, 413);
  }

  let parsed: { audio_data?: string; mime_type?: string; language?: string };
  try {
    parsed = JSON.parse(rawBody);
  } catch {
    return errorResponse("Invalid JSON body", 400);
  }

  const { audio_data, mime_type = "audio/wav", language = "en-US" } = parsed;
  if (!audio_data) return errorResponse("Missing audio_data", 400);

  // Build prompt with language hint for better accuracy on African languages
  const transcribePrompt = `Transcribe the following clinical consultation audio accurately in ${language}. `
    + `Return only the transcription text with no commentary, labels, or formatting.`;

  const geminiBody = {
    contents: [{
      parts: [
        { inlineData: { mimeType: mime_type, data: audio_data } },
        { text: transcribePrompt },
      ],
    }],
    generationConfig: {
      temperature: 0,       // Deterministic for transcription
      maxOutputTokens: 8192,
    },
  };

  const url = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${env.GEMINI_API_KEY}`;

  const upstream = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(geminiBody),
  });

  if (!upstream.ok) {
    const errText = await upstream.text();
    console.log(`gemini_stt_error status=${upstream.status} body=${errText.substring(0, 200)}`);
    return errorResponse(`Gemini STT error: ${upstream.status}`, upstream.status);
  }

  // Parse Gemini response and return a normalised transcript object
  const geminiResponse = await upstream.json() as {
    candidates?: Array<{ content?: { parts?: Array<{ text?: string }> } }>;
  };

  const transcript = geminiResponse.candidates?.[0]?.content?.parts?.[0]?.text?.trim() ?? "";
  return jsonResponse({ transcript });
}

async function proxyDeepgram(request: Request, env: Env): Promise<Response> {
  const sizeErr = checkContentLength(request, MAX_AUDIO_BODY_BYTES);
  if (sizeErr) return errorResponse(sizeErr, 413);

  // Whitelist query params to prevent abuse
  const rawQuery = request.headers.get("X-ChartLite-Query") || "";
  const sanitizedParams = new URLSearchParams();
  for (const [key, value] of new URLSearchParams(rawQuery)) {
    if (ALLOWED_DEEPGRAM_PARAMS.has(key)) {
      sanitizedParams.set(key, value);
    }
  }

  const audioContentType = request.headers.get("X-ChartLite-Audio-Type") || "audio/wav";
  const audioBody = await request.arrayBuffer();
  if (audioBody.byteLength > MAX_AUDIO_BODY_BYTES) {
    return errorResponse(`Request body too large (max ${Math.round(MAX_AUDIO_BODY_BYTES / 1_048_576)}MB)`, 413);
  }

  const url = `https://api.deepgram.com/v1/listen?${sanitizedParams.toString()}`;

  const upstream = await fetch(url, {
    method: "POST",
    headers: {
      "Authorization": `Token ${env.DEEPGRAM_API_KEY}`,
      "Content-Type": audioContentType,
    },
    body: audioBody,
  });

  if (!upstream.ok) {
    const errText = await upstream.text();
    console.log(`deepgram_error status=${upstream.status} body=${errText.substring(0, 200)}`);
    return errorResponse(`Deepgram error: ${upstream.status}`, upstream.status);
  }

  const responseBody = await upstream.text();
  return new Response(responseBody, {
    status: upstream.status,
    headers: { "Content-Type": "application/json" },
  });
}

async function proxyOpenAI(request: Request, env: Env): Promise<Response> {
  const sizeErr = checkContentLength(request, MAX_AUDIO_BODY_BYTES);
  if (sizeErr) return errorResponse(sizeErr, 413);

  const formData = await request.formData();

  // Rebuild the form — only allow known safe fields
  const upstreamForm = new FormData();
  const file = formData.get("file");
  if (!file) return errorResponse("Missing audio file", 400);
  if (typeof (file as any).size === 'number' && (file as any).size > MAX_AUDIO_BODY_BYTES) {
    return errorResponse(`Request body too large (max ${Math.round(MAX_AUDIO_BODY_BYTES / 1_048_576)}MB)`, 413);
  }
  upstreamForm.append("file", file);

  // Force model to our allowed value
  upstreamForm.append("model", "gpt-4o-transcribe");
  const language = formData.get("language");
  if (language && typeof language === "string" && language.length <= 5) {
    upstreamForm.append("language", language);
  }
  upstreamForm.append("response_format", "json");

  const upstream = await fetch("https://api.openai.com/v1/audio/transcriptions", {
    method: "POST",
    headers: { "Authorization": `Bearer ${env.OPENAI_API_KEY}` },
    body: upstreamForm,
  });

  if (!upstream.ok) {
    const errText = await upstream.text();
    console.log(`openai_error status=${upstream.status} body=${errText.substring(0, 200)}`);
    return errorResponse(`OpenAI error: ${upstream.status}`, upstream.status);
  }

  const responseBody = await upstream.text();
  return new Response(responseBody, {
    status: upstream.status,
    headers: { "Content-Type": "application/json" },
  });
}

// ── Claude Extraction Proxy ──

async function proxyClaudeMessages(request: Request, env: Env): Promise<Response> {
  const sizeErr = checkContentLength(request, MAX_CLAUDE_BODY_BYTES);
  if (sizeErr) return errorResponse(sizeErr, 413);

  const rawBody = await request.text();
  if (new TextEncoder().encode(rawBody).byteLength > MAX_CLAUDE_BODY_BYTES) {
    return errorResponse(`Request body too large (max ${Math.round(MAX_CLAUDE_BODY_BYTES / 1_048_576)}MB)`, 413);
  }
  const startMs = Date.now();

  // Validate and constrain the request
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(rawBody);
  } catch {
    return errorResponse("Invalid JSON body", 400);
  }

  // Enforce allowed model
  const model = String(parsed.model || "");
  if (!ALLOWED_CLAUDE_MODELS.has(model)) {
    return errorResponse(`Model not allowed: ${model}`, 400);
  }

  // Cap max_tokens
  const maxTokens = Math.min(Number(parsed.max_tokens) || 2048, MAX_CLAUDE_TOKENS);

  // Whitelist only expected fields — discard everything else
  const sanitizedBody: Record<string, unknown> = {
    model,
    max_tokens: maxTokens,
    messages: parsed.messages,
  };
  if (parsed.system !== undefined) {
    if (typeof parsed.system === "string" || Array.isArray(parsed.system)) {
      sanitizedBody.system = parsed.system;
    }
  }
  if (typeof parsed.temperature === "number") {
    sanitizedBody.temperature = parsed.temperature;
  }
  if (typeof parsed.top_p === "number") {
    sanitizedBody.top_p = parsed.top_p;
  }

  // Forward anthropic-version from client if provided, otherwise use default
  const anthropicVersion = request.headers.get("X-Anthropic-Version") || "2023-06-01";

  const upstream = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "x-api-key": env.ANTHROPIC_API_KEY,
      "anthropic-version": anthropicVersion,
      "content-type": "application/json",
    },
    body: JSON.stringify(sanitizedBody),
  });

  if (!upstream.ok) {
    const errText = await upstream.text();
    console.log(`claude_error status=${upstream.status} body=${errText.substring(0, 200)}`);
    return errorResponse(`Claude error: ${upstream.status}`, upstream.status);
  }

  const responseBody = await upstream.text();
  console.log(`claude status=${upstream.status} latency=${Date.now() - startMs}ms`);

  return new Response(responseBody, {
    status: upstream.status,
    headers: { "Content-Type": "application/json" },
  });
}

async function proxyGeminiExtract(request: Request, env: Env): Promise<Response> {
  const sizeErr = checkContentLength(request, MAX_CLAUDE_BODY_BYTES);
  if (sizeErr) return errorResponse(sizeErr, 413);

  const rawBody = await request.text();
  if (new TextEncoder().encode(rawBody).byteLength > MAX_CLAUDE_BODY_BYTES) {
    return errorResponse("Request body too large", 413);
  }

  let parsed: Record<string, unknown>;
  try { parsed = JSON.parse(rawBody); } catch { return errorResponse("Invalid JSON body", 400); }

  // Validate model if provided, otherwise use server default
  const clientModel = String(parsed.model || "");
  const model = clientModel && ALLOWED_GEMINI_EXTRACT_MODELS.has(clientModel) ? clientModel : GEMINI_MODEL;
  if (clientModel && !ALLOWED_GEMINI_EXTRACT_MODELS.has(clientModel)) {
    return errorResponse(`Model not allowed: ${clientModel}`, 400);
  }

  const system = typeof parsed.system === "string" ? parsed.system : "";
  const messages = Array.isArray(parsed.messages) ? parsed.messages : [];
  const userMessage = (messages[0] as any)?.content ?? "";
  const maxTokens = Math.min(Number(parsed.max_tokens) || 2048, 8192);

  const prompt = system ? `${system}\n\n${userMessage}` : String(userMessage);

  const geminiBody = {
    contents: [{ parts: [{ text: prompt }] }],
    generationConfig: { temperature: 0.1, maxOutputTokens: maxTokens },
  };

  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${env.GEMINI_API_KEY}`;
  const startMs = Date.now();

  const upstream = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(geminiBody),
  });

  if (!upstream.ok) {
    const errText = await upstream.text();
    console.log(`gemini_extract_error status=${upstream.status} body=${errText.substring(0, 200)}`);
    return errorResponse(`Gemini extract error: ${upstream.status}`, upstream.status);
  }

  const geminiResp = await upstream.json() as any;
  const text = geminiResp?.candidates?.[0]?.content?.parts?.[0]?.text?.trim() ?? "";
  console.log(`gemini_extract status=200 latency=${Date.now() - startMs}ms`);

  // Return in a normalised format the Android strategy can parse
  return jsonResponse({ text });
}

async function proxyOpenAIExtract(request: Request, env: Env): Promise<Response> {
  const sizeErr = checkContentLength(request, MAX_CLAUDE_BODY_BYTES);
  if (sizeErr) return errorResponse(sizeErr, 413);

  const rawBody = await request.text();
  if (new TextEncoder().encode(rawBody).byteLength > MAX_CLAUDE_BODY_BYTES) {
    return errorResponse("Request body too large", 413);
  }

  let parsed: Record<string, unknown>;
  try { parsed = JSON.parse(rawBody); } catch { return errorResponse("Invalid JSON body", 400); }

  const model = String(parsed.model || "");
  if (!ALLOWED_OPENAI_EXTRACT_MODELS.has(model)) {
    return errorResponse(`OpenAI model not allowed: ${model}`, 400);
  }

  const system = typeof parsed.system === "string" ? parsed.system : "";
  const messages = Array.isArray(parsed.messages) ? parsed.messages : [];
  const maxTokens = Math.min(Number(parsed.max_tokens) || 2048, 4096);

  // Build OpenAI chat completions format
  const openaiMessages: Array<{role: string; content: string}> = [];
  if (system) openaiMessages.push({ role: "system", content: system });
  for (const msg of messages) {
    const m = msg as any;
    if (m.role && m.content) openaiMessages.push({ role: m.role, content: String(m.content) });
  }

  const openaiBody = { model, messages: openaiMessages, max_tokens: maxTokens };
  const startMs = Date.now();

  const upstream = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${env.OPENAI_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(openaiBody),
  });

  if (!upstream.ok) {
    const errText = await upstream.text();
    console.log(`openai_extract_error model=${model} status=${upstream.status} body=${errText.substring(0, 200)}`);
    return errorResponse(`OpenAI extract error: ${upstream.status}`, upstream.status);
  }

  const openaiResp = await upstream.json() as any;
  const text = openaiResp?.choices?.[0]?.message?.content?.trim() ?? "";
  console.log(`openai_extract model=${model} status=200 latency=${Date.now() - startMs}ms`);

  return jsonResponse({ text });
}

// ── Router ──

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // No CORS — this is a native Android app, not a browser client
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204 });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    // Health check (no auth required)
    if (path === "/v1/health" && request.method === "GET") {
      return jsonResponse({ status: "ok", version: "1.0.0" });
    }

    // Session exchange endpoint (no auth required — it IS the auth)
    if (path === "/v1/auth/session" && request.method === "POST") {
      // Rate limit session exchanges by IP (prevents brute-force attestation)
      const clientIp = getClientIp(request);
      if (checkRateLimit(clientIp, ipRateLimits, IP_RATE_WINDOW_MS, 10)) { // Stricter: 10/min
        return errorResponse("Rate limit exceeded", 429);
      }
      return handleSessionExchange(request, env);
    }

    if (path === "/v1/device/generate-code" && request.method === "POST") {
      const clientIp = getClientIp(request);
      if (checkRateLimit(clientIp, ipRateLimits, IP_RATE_WINDOW_MS, 5)) {
        return errorResponse("Rate limit exceeded", 429);
      }
      return handleGenerateCode(request, env);
    }

    if (path === "/v1/auth/device/enroll" && request.method === "POST") {
      const clientIp = getClientIp(request);
      if (checkRateLimit(clientIp, ipRateLimits, IP_RATE_WINDOW_MS, 10)) {
        return errorResponse("Rate limit exceeded", 429);
      }
      return handleDeviceEnroll(request, env);
    }

    if (path === "/v1/auth/device/challenge" && request.method === "POST") {
      const clientIp = getClientIp(request);
      if (checkRateLimit(clientIp, ipRateLimits, IP_RATE_WINDOW_MS, 20)) {
        return errorResponse("Rate limit exceeded", 429);
      }
      return handleDeviceChallenge(request, env);
    }

    if (path === "/v1/auth/device/session" && request.method === "POST") {
      const clientIp = getClientIp(request);
      if (checkRateLimit(clientIp, ipRateLimits, IP_RATE_WINDOW_MS, 20)) {
        return errorResponse("Rate limit exceeded", 429);
      }
      return handleDeviceSession(request, env);
    }

    // Auth check for all other endpoints
    const auth = await authenticate(request, env);
    if (!auth.authorized) {
      return errorResponse("Unauthorized", 401);
    }

    // Rate limit: IP first (abuse barrier), then per-device (trust-differentiated)
    const clientIp = getClientIp(request);
    if (checkRateLimit(clientIp, ipRateLimits, IP_RATE_WINDOW_MS, IP_RATE_MAX_REQUESTS)) {
      console.log(`rate_limited ip=${clientIp} auth=${auth.authMethod}`);
      return errorResponse("Rate limit exceeded", 429);
    }

    const deviceMax = auth.authMethod === "integrity" ? DEVICE_RATE_INTEGRITY : DEVICE_RATE_DEVICE_KEY;
    if (checkRateLimit(auth.deviceId, deviceRateLimits, DEVICE_RATE_WINDOW_MS, deviceMax)) {
      console.log(`rate_limited device=${auth.deviceId.substring(0, 8)}... auth=${auth.authMethod} limit=${deviceMax}`);
      return errorResponse("Rate limit exceeded", 429);
    }

    // Periodic cleanup to prevent unbounded growth
    if (ipRateLimits.size + deviceRateLimits.size > 2000) {
      cleanupRateLimits();
    }

    // Route to handler
    if (request.method === "POST") {
      switch (path) {
        case "/v1/transcribe":
          return handleTranscribe(request, env);
        case "/v1/extract":
        case "/v1/generate-note": {
          const aiProvider = request.headers.get("X-ChartLite-AI-Provider") || "claude";
          if (!ALLOWED_EXTRACT_PROVIDERS.has(aiProvider)) {
            return errorResponse(`Unknown AI provider: ${aiProvider}`, 400);
          }
          if (aiProvider === "gemini") return proxyGeminiExtract(request, env);
          if (aiProvider === "openai") return proxyOpenAIExtract(request, env);
          return proxyClaudeMessages(request, env);
        }
      }
    }

    return errorResponse("Not found", 404);
  },
};
