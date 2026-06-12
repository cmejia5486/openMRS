import { defineConfig } from "vitest/config";
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.toml" },
      miniflare: {
        bindings: {
          DEVICE_ENROLLMENT_SECRET: "test-device-enrollment-code",
          SESSION_SIGNING_SECRET: "test-session-secret-for-unit-tests",
          GOOGLE_SERVICE_ACCOUNT_KEY: JSON.stringify({
            client_email: "test@test.iam.gserviceaccount.com",
            private_key: "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg==\n-----END PRIVATE KEY-----\n",
            token_uri: "https://oauth2.googleapis.com/token",
          }),
          GOOGLE_STT_API_KEY: "test-google-stt-key",
          DEEPGRAM_API_KEY: "test-deepgram-key",
          OPENAI_API_KEY: "test-openai-key",
          ANTHROPIC_API_KEY: "test-anthropic-key",
          ENVIRONMENT: "test",
        },
      },
    }),
  ],
  test: {
    include: ["test/**/*.test.ts"],
  },
});
