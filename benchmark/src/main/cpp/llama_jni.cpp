#include <jni.h>
#include <android/log.h>
#include <string>
#include <vector>
#include <mutex>
#include <unistd.h>

#include "llama.h"
#include "ggml.h"

#define TAG "LlamaCppBench"
#define LOGi(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGe(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

static llama_model  *g_model  = nullptr;
static llama_context *g_ctx   = nullptr;
static const llama_vocab *g_vocab = nullptr;
static std::mutex g_mutex;

// ── Metrics from last generation ──
static double g_last_load_ms     = 0;
static double g_last_prefill_ms  = 0;
static double g_last_decode_ms   = 0;
static int    g_last_prompt_tokens  = 0;
static int    g_last_decode_tokens  = 0;

extern "C" {

JNIEXPORT jboolean JNICALL
Java_com_chartlite_benchmark_engine_LlamaCppBridge_nativeLoadModel(
    JNIEnv *env, jobject, jstring jModelPath, jint nThreads
) {
    std::lock_guard<std::mutex> lock(g_mutex);

    // Unload previous
    if (g_ctx)   { llama_free(g_ctx);        g_ctx = nullptr; }
    if (g_model) { llama_model_free(g_model); g_model = nullptr; }
    g_vocab = nullptr;

    const char *path = env->GetStringUTFChars(jModelPath, nullptr);
    LOGi("Loading GGUF model: %s (threads=%d)", path, nThreads);

    auto t0 = ggml_time_us();

    // Load model
    auto mparams = llama_model_default_params();
    mparams.n_gpu_layers = 0; // CPU only for fair comparison
    g_model = llama_model_load_from_file(path, mparams);
    env->ReleaseStringUTFChars(jModelPath, path);

    if (!g_model) {
        LOGe("Failed to load model");
        return JNI_FALSE;
    }

    g_vocab = llama_model_get_vocab(g_model);

    // Create context
    auto cparams = llama_context_default_params();
    cparams.n_ctx    = 2048;
    cparams.n_batch  = 512;
    cparams.n_threads = nThreads > 0 ? nThreads : 4;
    cparams.n_threads_batch = cparams.n_threads;

    g_ctx = llama_init_from_model(g_model, cparams);
    if (!g_ctx) {
        LOGe("Failed to create context");
        llama_model_free(g_model);
        g_model = nullptr;
        g_vocab = nullptr;
        return JNI_FALSE;
    }

    g_last_load_ms = (ggml_time_us() - t0) / 1000.0;
    LOGi("Model loaded in %.0f ms", g_last_load_ms);
    return JNI_TRUE;
}

JNIEXPORT jstring JNICALL
Java_com_chartlite_benchmark_engine_LlamaCppBridge_nativeGenerate(
    JNIEnv *env, jobject,
    jstring jPrompt, jint maxTokens, jfloat temperature
) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_ctx || !g_model || !g_vocab) {
        LOGe("Model not loaded");
        return nullptr;
    }

    const char *promptRaw = env->GetStringUTFChars(jPrompt, nullptr);
    std::string prompt(promptRaw);
    env->ReleaseStringUTFChars(jPrompt, promptRaw);

    // Tokenize
    std::vector<llama_token> tokens(prompt.size() + 32);
    int n_tokens = llama_tokenize(g_vocab, prompt.c_str(), prompt.size(),
                                  tokens.data(), tokens.size(), true, true);
    if (n_tokens < 0) {
        tokens.resize(-n_tokens);
        n_tokens = llama_tokenize(g_vocab, prompt.c_str(), prompt.size(),
                                  tokens.data(), tokens.size(), true, true);
    }
    tokens.resize(n_tokens);
    g_last_prompt_tokens = n_tokens;

    LOGi("Prompt: %d tokens, generating up to %d tokens", n_tokens, maxTokens);

    // Clear KV cache
    llama_memory_clear(llama_get_memory(g_ctx), true);

    // Prefill
    auto t_prefill = ggml_time_us();
    llama_batch batch = llama_batch_get_one(tokens.data(), n_tokens);
    if (llama_decode(g_ctx, batch) != 0) {
        LOGe("Prefill decode failed");
        return nullptr;
    }
    g_last_prefill_ms = (ggml_time_us() - t_prefill) / 1000.0;

    // Decode
    auto t_decode = ggml_time_us();
    std::string result;
    result.reserve(4096);

    auto *smpl = llama_sampler_chain_init(llama_sampler_chain_default_params());
    llama_sampler_chain_add(smpl, llama_sampler_init_temp(temperature));
    llama_sampler_chain_add(smpl, llama_sampler_init_dist(42));

    int n_decoded = 0;
    for (int i = 0; i < maxTokens; i++) {
        llama_token new_token = llama_sampler_sample(smpl, g_ctx, -1);

        if (llama_vocab_is_eog(g_vocab, new_token)) break;

        // Convert token to text
        char buf[256];
        int len = llama_token_to_piece(g_vocab, new_token, buf, sizeof(buf), 0, true);
        if (len > 0) {
            result.append(buf, len);
        }

        // Prepare next batch (single token)
        llama_batch next = llama_batch_get_one(&new_token, 1);
        if (llama_decode(g_ctx, next) != 0) {
            LOGe("Decode failed at token %d", i);
            break;
        }
        n_decoded++;
    }

    llama_sampler_free(smpl);

    g_last_decode_ms = (ggml_time_us() - t_decode) / 1000.0;
    g_last_decode_tokens = n_decoded;

    double prefill_tps = g_last_prompt_tokens > 0 && g_last_prefill_ms > 0
        ? g_last_prompt_tokens / (g_last_prefill_ms / 1000.0) : 0;
    double decode_tps = n_decoded > 0 && g_last_decode_ms > 0
        ? n_decoded / (g_last_decode_ms / 1000.0) : 0;

    LOGi("Done: prefill=%d tok (%.1f tok/s, %.0fms), decode=%d tok (%.1f tok/s, %.0fms)",
         g_last_prompt_tokens, prefill_tps, g_last_prefill_ms,
         n_decoded, decode_tps, g_last_decode_ms);

    if (result.empty()) return nullptr;
    return env->NewStringUTF(result.c_str());
}

JNIEXPORT jdoubleArray JNICALL
Java_com_chartlite_benchmark_engine_LlamaCppBridge_nativeGetMetrics(JNIEnv *env, jobject) {
    // Returns: [load_ms, prefill_ms, decode_ms, prompt_tokens, decode_tokens]
    jdoubleArray arr = env->NewDoubleArray(5);
    double metrics[5] = {
        g_last_load_ms,
        g_last_prefill_ms,
        g_last_decode_ms,
        (double)g_last_prompt_tokens,
        (double)g_last_decode_tokens
    };
    env->SetDoubleArrayRegion(arr, 0, 5, metrics);
    return arr;
}

JNIEXPORT void JNICALL
Java_com_chartlite_benchmark_engine_LlamaCppBridge_nativeUnload(JNIEnv *, jobject) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_ctx)   { llama_free(g_ctx);        g_ctx = nullptr; }
    if (g_model) { llama_model_free(g_model); g_model = nullptr; }
    g_vocab = nullptr;
    LOGi("Model unloaded");
}

} // extern "C"
