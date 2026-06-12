#include <jni.h>
#include <android/log.h>
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <string>
#include <sstream>
#include <atomic>
#include <mutex>
#include <vector>
#include <unistd.h>

#include <llm/llm.hpp>
#include <MNN/expr/Expr.hpp>
#include <MNN/expr/NeuralNetWorkOp.hpp>

#define TAG "ChartLiteLLM"
#define LOGi(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGw(...) __android_log_print(ANDROID_LOG_WARN,  TAG, __VA_ARGS__)
#define LOGe(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

using namespace MNN::Transformer;

namespace {

struct CpuProfile {
    int total_cores = 1;
    int perf_cores = 1;
    long max_freq_khz = 0;
    long little_max_freq_khz = 0;
    bool symmetric_soc = true;
    std::vector<int> perf_core_ids;
};

static CpuProfile detect_cpu_profile() {
    CpuProfile profile;
    profile.total_cores = std::max(1, (int)sysconf(_SC_NPROCESSORS_ONLN));

    std::vector<long> freqs(profile.total_cores, 0);
    for (int i = 0; i < profile.total_cores; ++i) {
        char path[128];
        snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/cpufreq/cpuinfo_max_freq", i);
        FILE* f = fopen(path, "r");
        if (!f) {
            continue;
        }
        long freq = 0;
        if (fscanf(f, "%ld", &freq) == 1 && freq > 0) {
            freqs[i] = freq;
            profile.max_freq_khz = std::max(profile.max_freq_khz, freq);
        }
        fclose(f);
    }

    if (profile.max_freq_khz <= 0) {
        profile.perf_cores = profile.total_cores;
        profile.symmetric_soc = true;
        for (int i = 0; i < profile.total_cores; ++i) {
            profile.perf_core_ids.push_back(i);
        }
        return profile;
    }

    const long perf_threshold = std::max(1L, (long)std::lround(profile.max_freq_khz * 0.8));
    for (int i = 0; i < profile.total_cores; ++i) {
        if (freqs[i] >= perf_threshold) {
            profile.perf_core_ids.push_back(i);
        } else if (freqs[i] > profile.little_max_freq_khz) {
            profile.little_max_freq_khz = freqs[i];
        }
    }

    if (profile.perf_core_ids.empty()) {
        for (int i = 0; i < profile.total_cores; ++i) {
            if (freqs[i] == profile.max_freq_khz || freqs[i] == 0) {
                profile.perf_core_ids.push_back(i);
            }
        }
    }

    if (profile.perf_core_ids.empty()) {
        for (int i = 0; i < profile.total_cores; ++i) {
            profile.perf_core_ids.push_back(i);
        }
    }

    profile.perf_cores = std::max(1, (int)profile.perf_core_ids.size());
    profile.symmetric_soc = profile.perf_cores == profile.total_cores || profile.little_max_freq_khz == 0;
    return profile;
}

static int compute_littlecore_decrease_rate(const CpuProfile& profile) {
    if (profile.symmetric_soc || profile.max_freq_khz <= 0 || profile.little_max_freq_khz <= 0) {
        return 50;
    }
    const double ratio = (double)profile.little_max_freq_khz * 100.0 / (double)profile.max_freq_khz;
    return std::max(35, std::min(85, (int)std::lround(ratio)));
}

} // namespace

// Global state — single model at a time (singleton pattern)
static Llm *g_llm = nullptr;
static std::mutex g_mutex;

// Sampling parameters (applied via set_config JSON)
static float g_temperature    = 0.3f;
static int   g_max_tokens     = 2048;
static float g_top_p          = 0.95f;
static int   g_top_k          = 40;
static float g_repeat_penalty = 1.0f;
static std::atomic<bool> g_cancel_generation(false);

static std::string escape_json_string(const std::string& value) {
    std::string escaped;
    escaped.reserve(value.size() + 8);
    for (char ch : value) {
        switch (ch) {
            case '\\':
                escaped += "\\\\";
                break;
            case '"':
                escaped += "\\\"";
                break;
            default:
                escaped += ch;
                break;
        }
    }
    return escaped;
}

// Build JSON config string for MNN sampling parameters
static std::string build_config_json() {
    std::ostringstream ss;
    ss << "{"
       << "\"max_new_tokens\":" << g_max_tokens << ","
       << "\"sampler_type\":\"mixed\","
       << "\"mixed_samplers\":[\"penalty\",\"topK\",\"topP\",\"temperature\"],"
       << "\"temperature\":" << g_temperature << ","
       << "\"topK\":" << g_top_k << ","
       << "\"topP\":" << g_top_p << ","
       << "\"penalty\":" << g_repeat_penalty << ","
       << "\"penalty_sampler\":\"temperature\""
       << "}";
    return ss.str();
}

// Apply current sampling params to the loaded model
static void apply_params() {
    if (!g_llm) return;
    std::string config = build_config_json();
    g_llm->set_config(config);
}

// Custom output stream buffer that checks cancellation.
// Pre-reserves 16 KB to avoid O(n^2) reallocation from char-by-char overflow() calls.
class CancelCheckBuf : public std::streambuf {
public:
    std::string result;
    CancelCheckBuf() { result.reserve(16384); }
protected:
    int overflow(int c) override {
        if (g_cancel_generation.load()) return EOF;
        if (c != EOF) result += static_cast<char>(c);
        return c;
    }
    std::streamsize xsputn(const char* s, std::streamsize n) override {
        if (g_cancel_generation.load()) return 0;
        result.append(s, n);
        return n;
    }
};

// ── JNI Methods ──
// Note: JNI names use LlamaBridge for backward compatibility with Kotlin wrapper.
// The Kotlin class name remains LlamaBridge to avoid touching all callers,
// but the native implementation now uses MNN.

extern "C" JNIEXPORT void JNICALL
Java_com_chartlite_llm_LlamaBridge_nativeInit(JNIEnv *, jobject) {
    // MNN doesn't need a global backend init — this is a no-op for API compatibility
    LOGi("MNN backend ready");
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_chartlite_llm_LlamaBridge_nativeInitGenerateModel(JNIEnv *env, jobject, jstring jModelPath, jstring jTmpPath) {
    std::lock_guard<std::mutex> lock(g_mutex);

    // Shutdown previous model if any
    if (g_llm) {
        Llm::destroy(g_llm);
        g_llm = nullptr;
    }

    const char *modelPath = env->GetStringUTFChars(jModelPath, nullptr);
    const char *tmpPathChars = env->GetStringUTFChars(jTmpPath, nullptr);
    LOGi("initGenerateModel (MNN): %s", modelPath);

    // MNN expects path to the directory containing llm_config.json, with trailing /
    std::string configDir(modelPath);
    std::string tmpPath = tmpPathChars ? tmpPathChars : "";
    if (!configDir.empty() && configDir.back() != '/') {
        configDir += '/';
    }
    g_llm = Llm::createLLM(configDir);
    env->ReleaseStringUTFChars(jModelPath, modelPath);
    if (tmpPathChars) {
        env->ReleaseStringUTFChars(jTmpPath, tmpPathChars);
    }

    if (!g_llm) {
        LOGe("Llm::createLLM failed");
        return JNI_FALSE;
    }

    const CpuProfile cpu_profile = detect_cpu_profile();
    const int n_cpu = cpu_profile.total_cores;

    // Get total RAM for logging
    long page_count = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGE_SIZE);
    double total_ram_gb = 0.0;
    if (page_count > 0 && page_size > 0) {
        total_ram_gb = (double)page_count * (double)page_size / (1024.0 * 1024.0 * 1024.0);
    }
    const bool low_ram_device = total_ram_gb <= 3.5;
    const bool ultra_low_ram = total_ram_gb <= 3.0;
    const bool symmetric_soc = cpu_profile.symmetric_soc;

    // Thread count:
    // - asymmetric SoCs: stay on the performance cluster to avoid decode stalls from little cores
    // - symmetric SoCs: use more threads because each core is weak, but keep ultra-low-RAM devices tighter
    int n_threads;
    std::vector<int> pinned_core_ids;
    if (!symmetric_soc && !cpu_profile.perf_core_ids.empty()) {
        const int perf_cap = low_ram_device ? (ultra_low_ram ? 2 : 3) : 4;
        n_threads = std::max(1, std::min(cpu_profile.perf_cores, perf_cap));
        pinned_core_ids.assign(cpu_profile.perf_core_ids.begin(), cpu_profile.perf_core_ids.begin() + n_threads);
    } else if (low_ram_device) {
        n_threads = std::min(n_cpu, ultra_low_ram ? 4 : 6);
    } else {
        n_threads = std::min(n_cpu, 4);
    }
    if (n_cpu > 1 && (pinned_core_ids.empty() || pinned_core_ids.size() >= 2)) {
        n_threads = std::max(2, n_threads);
    } else if (!pinned_core_ids.empty()) {
        n_threads = (int)pinned_core_ids.size();
    }

    const int init_threads = std::max(
        1,
        std::min(
            ultra_low_ram ? 2 : (low_ram_device ? 2 : 4),
            pinned_core_ids.empty() ? n_threads : (int)pinned_core_ids.size()
        )
    );
    const int attention_mode = low_ram_device ? 10 : 8;
    const int littlecore_decrease_rate = compute_littlecore_decrease_rate(cpu_profile);

    // Use the MNN-documented runtime keys so low-RAM tuning is actually applied.
    //
    // On ultra-low-RAM (≤3GB): disable mmap to prevent page thrashing. The 390MB INT4
    // model gets demand-paged from slow eMMC, and the kernel aggressively reclaims clean
    // mmap pages under memory pressure, causing repeated page faults during decode.
    // Loading into committed memory trades slower initial load for stable decode speed.
    //
    // KV cache disk offloading: on low-RAM devices, spill KV cache to tmp_path so model
    // weights stay in RAM. Each decode token only touches the hot KV tail.
    const bool use_mmap = !ultra_low_ram;  // Disable mmap on ≤3GB
    const bool kvcache_to_disk = low_ram_device && !tmpPath.empty();

    std::ostringstream config;
    config << "{"
           << "\"async\":false,"
           << "\"thread_num\":" << n_threads << ","
           << "\"init_thread_number\":" << init_threads << ","
           << "\"backend_type\":\"cpu\","
           << "\"precision\":\"low\","
           << "\"memory\":\"low\","
            << "\"power\":\"high\","
           << "\"cpu_littlecore_decrease_rate\":" << littlecore_decrease_rate << ","
           << "\"use_mmap\":" << (use_mmap ? "true" : "false") << ","
           << "\"use_cached_mmap\":" << (use_mmap ? "true" : "false") << ",";
    if (!pinned_core_ids.empty()) {
        config << "\"cpu_core_ids\":[";
        for (size_t i = 0; i < pinned_core_ids.size(); ++i) {
            if (i > 0) config << ",";
            config << pinned_core_ids[i];
        }
        config << "],";
    }
    if (!tmpPath.empty()) {
        config << "\"tmp_path\":\"" << escape_json_string(tmpPath) << "\",";
    }
    if (kvcache_to_disk) {
        config << "\"kvcache_mmap\":true,";
    }
    config << "\"attention_mode\":" << attention_mode << ","
           << "\"jinja\":{\"context\":{\"enable_thinking\":false}}"
           << "}";
    if (!g_llm->set_config(config.str())) {
        LOGw("Initial MNN config rejected, continuing with model defaults");
    }

    // Load model weights
    if (!g_llm->load()) {
        LOGe("Llm::load() failed");
        Llm::destroy(g_llm);
        g_llm = nullptr;
        return JNI_FALSE;
    }

    // Apply current sampling parameters
    apply_params();

    // Skip OP_ENCODER_NUMBER tuning on CPU. In this vendored MNN tree the hint is
    // consumed by OpenCL / Metal backends, so the extra warm-up pass only adds load time.

    LOGi(
        "MNN model loaded: ram=%.1fGB, threads=%d, init_threads=%d, perf_cores=%d, attention=%d, low_ram=%d, mmap=%d, kv_disk=%d, symmetric=%d, pinned=%d",
        total_ram_gb,
        n_threads,
        init_threads,
        cpu_profile.perf_cores,
        attention_mode,
        low_ram_device ? 1 : 0,
        use_mmap ? 1 : 0,
        kvcache_to_disk ? 1 : 0,
        symmetric_soc ? 1 : 0,
        pinned_core_ids.empty() ? 0 : 1
    );
    return JNI_TRUE;
}

extern "C" JNIEXPORT void JNICALL
Java_com_chartlite_llm_LlamaBridge_nativeUpdateGenerateParams(
    JNIEnv *, jobject,
    jfloat temperature, jint maxTokens, jfloat topP, jint topK, jfloat repeatPenalty
) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_temperature    = temperature;
    g_max_tokens     = maxTokens;
    g_top_p          = topP;
    g_top_k          = topK;
    g_repeat_penalty = repeatPenalty;
    apply_params();
    LOGi("Params updated: temp=%.2f, max=%d, topP=%.2f, topK=%d, repeat=%.2f",
         g_temperature, g_max_tokens, g_top_p, g_top_k, g_repeat_penalty);
}

// Internal generate without mutex — called by locked entry points
static jstring generate_internal_jni(JNIEnv *env, jstring jPrompt) {
    if (!g_llm) {
        LOGe("generate_internal_jni: model not loaded");
        return nullptr;
    }
    const char *prompt = env->GetStringUTFChars(jPrompt, nullptr);
    if (!prompt) return nullptr;
    std::string promptStr(prompt);
    env->ReleaseStringUTFChars(jPrompt, prompt);

    g_cancel_generation.store(false);
    CancelCheckBuf buf;
    std::ostream os(&buf);
    LOGi("Generating response for prompt (%zu chars)...", promptStr.size());
    g_llm->response(promptStr, &os, nullptr, g_max_tokens);

    const auto *ctx = g_llm->getContext();
    if (ctx) {
        double prefill_ms = ctx->prefill_us / 1000.0;
        double decode_ms = ctx->decode_us / 1000.0;
        double prefill_tok_s = ctx->prompt_len > 0 && prefill_ms > 0 ? ctx->prompt_len / (prefill_ms / 1000.0) : 0;
        double decode_tok_s = ctx->gen_seq_len > 0 && decode_ms > 0 ? ctx->gen_seq_len / (decode_ms / 1000.0) : 0;
        LOGi("Generate metrics: prompt=%d tok (%.1f tok/s, %.0fms), decode=%d tok (%.1f tok/s, %.0fms)",
             ctx->prompt_len, prefill_tok_s, prefill_ms,
             ctx->gen_seq_len, decode_tok_s, decode_ms);
    }
    if (g_cancel_generation.load()) LOGw("Generation was cancelled");
    if (buf.result.empty()) return nullptr;
    return env->NewStringUTF(buf.result.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_chartlite_llm_LlamaBridge_nativeGenerate(JNIEnv *env, jobject, jstring jPrompt) {
    std::lock_guard<std::mutex> lock(g_mutex);
    return generate_internal_jni(env, jPrompt);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_chartlite_llm_LlamaBridge_nativeGenerateChat(
    JNIEnv *env, jobject,
    jstring jSystemPrompt, jstring jUserMessage
) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_llm) {
        LOGe("nativeGenerateChat: model not loaded");
        return nullptr;
    }

    const char *sys = env->GetStringUTFChars(jSystemPrompt, nullptr);
    if (!sys) { LOGe("nativeGenerateChat: GetStringUTFChars failed for system"); return nullptr; }
    const char *usr = env->GetStringUTFChars(jUserMessage, nullptr);
    if (!usr) { env->ReleaseStringUTFChars(jSystemPrompt, sys); LOGe("nativeGenerateChat: GetStringUTFChars failed for user"); return nullptr; }

    ChatMessages messages = {
        {"system", std::string(sys)},
        {"user",   std::string(usr)},
    };

    env->ReleaseStringUTFChars(jSystemPrompt, sys);
    env->ReleaseStringUTFChars(jUserMessage, usr);

    g_cancel_generation.store(false);

    CancelCheckBuf buf;
    std::ostream os(&buf);

    LOGi("GenerateChat: system=%zu chars, user=%zu chars",
         messages[0].second.size(), messages[1].second.size());

    // response(ChatMessages) applies the model's native chat template
    // with proper special token handling, then generates
    g_llm->response(messages, &os, nullptr, g_max_tokens);

    const auto *ctx = g_llm->getContext();
    if (ctx) {
        double prefill_ms = ctx->prefill_us / 1000.0;
        double decode_ms = ctx->decode_us / 1000.0;
        double prefill_tok_s = ctx->prompt_len > 0 && prefill_ms > 0 ? ctx->prompt_len / (prefill_ms / 1000.0) : 0;
        double decode_tok_s = ctx->gen_seq_len > 0 && decode_ms > 0 ? ctx->gen_seq_len / (decode_ms / 1000.0) : 0;
        LOGi("GenerateChat metrics: prompt=%d tok (%.1f tok/s, %.0fms), decode=%d tok (%.1f tok/s, %.0fms)",
             ctx->prompt_len, prefill_tok_s, prefill_ms,
             ctx->gen_seq_len, decode_tok_s, decode_ms);
    }

    if (g_cancel_generation.load()) {
        LOGw("Generation was cancelled");
    }

    if (buf.result.empty()) return nullptr;
    return env->NewStringUTF(buf.result.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_chartlite_llm_LlamaBridge_nativeGenerateJson(
    JNIEnv *env, jobject, jstring jPrompt, jstring /* jJsonSchema */
) {
    std::lock_guard<std::mutex> lock(g_mutex);
    LOGw("nativeGenerateJson: grammar not supported in MNN, using standard generation");
    return generate_internal_jni(env, jPrompt);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_chartlite_llm_LlamaBridge_nativeGenerateVision(
    JNIEnv *env, jobject,
    jstring jSystemPrompt, jstring jUserMessage, jbyteArray jRgbData, jint width, jint height
) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_llm) {
        LOGe("nativeGenerateVision: model not loaded");
        return nullptr;
    }

    // Extract JNI strings early to avoid leaks if later calls fail
    const char *sysRaw = env->GetStringUTFChars(jSystemPrompt, nullptr);
    if (!sysRaw) return nullptr;
    std::string sysStr(sysRaw);
    env->ReleaseStringUTFChars(jSystemPrompt, sysRaw);

    const char *usrRaw = env->GetStringUTFChars(jUserMessage, nullptr);
    if (!usrRaw) return nullptr;
    std::string usrStr(usrRaw);
    env->ReleaseStringUTFChars(jUserMessage, usrRaw);

    // Convert RGB byte array to MNN VARP tensor [1, height, width, 3] UINT8
    // Use GetPrimitiveArrayCritical for zero-copy access — avoids ~2.6 MB duplicate
    // native buffer that GetByteArrayElements would create for a 960x960 image.
    jsize dataLen = env->GetArrayLength(jRgbData);

    LOGi("GenerateVision: system=%zu chars, user=%zu chars, image=%dx%d (%d bytes)",
         sysStr.size(), usrStr.size(), (int)width, (int)height, (int)dataLen);

    // Create MNN VARP from raw RGB data
    auto imageVar = MNN::Express::_Input({1, (int)height, (int)width, 3}, MNN::Express::NHWC, halide_type_of<uint8_t>());
    auto imagePtr = imageVar->writeMap<uint8_t>();

    jbyte *rgbBytes = (jbyte*)env->GetPrimitiveArrayCritical(jRgbData, nullptr);
    if (!rgbBytes) { imageVar->unMap(); return nullptr; }
    memcpy(imagePtr, rgbBytes, dataLen);
    env->ReleasePrimitiveArrayCritical(jRgbData, rgbBytes, JNI_ABORT);

    imageVar->unMap();

    // Build MultimodalPrompt with image data in the images map
    MultimodalPrompt mp;
    std::ostringstream prompt;
    prompt << "<|im_start|>system\n" << sysStr << "<|im_end|>\n"
           << "<|im_start|>user\n"
           << "<img>clinical_photo</img>\n"
           << usrStr << "<|im_end|>\n"
           << "<|im_start|>assistant\n";
    mp.prompt_template = prompt.str();

    // Put the image VARP into the images map with the placeholder key
    PromptImagePart imgPart;
    imgPart.image_data = imageVar;
    imgPart.width = (int)width;
    imgPart.height = (int)height;
    mp.images["clinical_photo"] = imgPart;

    g_cancel_generation.store(false);

    CancelCheckBuf buf;
    std::ostream os(&buf);

    g_llm->response(mp, &os, nullptr, g_max_tokens);

    const auto *ctx = g_llm->getContext();
    if (ctx) {
        LOGi("GenerateVision metrics: prompt=%d tokens, decode=%d tokens, first_token_ms=%.1f, total_decode_ms=%.1f, vision_ms=%.1f",
             ctx->prompt_len, ctx->gen_seq_len,
             ctx->prefill_us / 1000.0, ctx->decode_us / 1000.0,
             ctx->vision_us / 1000.0);
    }

    if (g_cancel_generation.load()) {
        LOGw("Vision generation was cancelled");
    }

    if (buf.result.empty()) return nullptr;
    return env->NewStringUTF(buf.result.c_str());
}

extern "C" JNIEXPORT void JNICALL
Java_com_chartlite_llm_LlamaBridge_nativeCancelGeneration(JNIEnv *, jobject) {
    g_cancel_generation.store(true);
    LOGw("Cancellation requested");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_chartlite_llm_LlamaBridge_nativeApplyChatTemplate(
    JNIEnv *env, jobject,
    jstring jSystemPrompt, jstring jUserMessage, jboolean /* enableThinking */
) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_llm) {
        LOGe("applyChatTemplate: model not loaded");
        return nullptr;
    }

    const char *systemPrompt = env->GetStringUTFChars(jSystemPrompt, nullptr);
    if (!systemPrompt) { LOGe("applyChatTemplate: GetStringUTFChars failed for system"); return nullptr; }
    const char *userMessage  = env->GetStringUTFChars(jUserMessage, nullptr);
    if (!userMessage) { env->ReleaseStringUTFChars(jSystemPrompt, systemPrompt); LOGe("applyChatTemplate: GetStringUTFChars failed for user"); return nullptr; }

    // Use MNN's built-in chat template from model metadata
    ChatMessages messages = {
        {"system", std::string(systemPrompt)},
        {"user",   std::string(userMessage)},
    };

    env->ReleaseStringUTFChars(jSystemPrompt, systemPrompt);
    env->ReleaseStringUTFChars(jUserMessage, userMessage);

    try {
        std::string result = g_llm->apply_chat_template(messages);
        LOGi("applyChatTemplate: generated prompt (%zu chars)", result.size());
        return env->NewStringUTF(result.c_str());
    } catch (const std::exception &e) {
        LOGe("applyChatTemplate failed: %s", e.what());
        return nullptr;
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_chartlite_llm_LlamaBridge_nativeShutdown(JNIEnv *, jobject) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_llm) {
        Llm::destroy(g_llm);
        g_llm = nullptr;
    }
    LOGi("MNN model unloaded");
}
