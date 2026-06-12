package com.chartlite.app.extraction

import android.util.Log
import com.chartlite.app.model.Formulary
import com.chartlite.app.model.ICD10Index
import java.util.Locale
import kotlin.math.sqrt

/**
 * On-device vector store for clinical terminology retrieval (RAG).
 *
 * Instead of stuffing all 300 ICD-10 codes + 515 formulary drugs into every LLM prompt
 * (~6,000 tokens, 80% of the 8K context window), we embed them into lightweight vectors
 * and retrieve only the top-K most relevant entries per transcript.
 *
 * Uses sparse TF-IDF vectors — each entry stores only its non-zero dimensions (typically
 * 3-10 out of 500-1500 vocabulary terms), saving ~2.5 MB vs dense FloatArrays on 3GB devices.
 */
class ClinicalVectorStore(
    private val icd10: ICD10Index,
    private val formulary: Formulary
) {

    // ── Sparse vector representation ─────────────────────────────────────

    /**
     * Sparse vector: stores only non-zero (index, value) pairs.
     * For a typical clinical entry with 5 tokens, this is ~40 bytes vs ~4 KB dense.
     */
    class SparseVector(val indices: IntArray, val values: FloatArray) {
        companion object {
            val EMPTY = SparseVector(IntArray(0), FloatArray(0))
        }
    }

    // ── Indexed entries ─────────────────────────────────────────────────

    data class IndexedEntry(
        val type: EntryType,
        val code: String,
        val name: String,
        val fullDetail: String,      // Rich text for prompt (includes keywords, aliases, routes)
        val searchableText: String,   // Lowercased, normalized for matching
        val vector: SparseVector      // Sparse TF-IDF vector
    ) {
        enum class EntryType { ICD10, DRUG }

        override fun equals(other: Any?) = other is IndexedEntry && code == other.code && type == other.type
        override fun hashCode() = 31 * type.hashCode() + code.hashCode()
    }

    private var entries: List<IndexedEntry> = emptyList()
    private var vocabulary: Map<String, Int> = emptyMap()
    private var idfWeights: FloatArray = floatArrayOf()
    private var indexed = false

    // ── Indexing ─────────────────────────────────────────────────────────

    /**
     * Build the vector index from ICD-10 and formulary data.
     * Call once at app startup after loading country data (~20-50ms).
     */
    @Synchronized
    fun buildIndex() {
        if (indexed) return
        val allEntries = mutableListOf<IndexedEntry>()

        // Index ICD-10 codes
        for (entry in icd10.codes) {
            val keywords = entry.keywords.joinToString(" ")
            val localTerms = entry.localTerms.values.flatten().joinToString(" ")
            val searchable = "${entry.code} ${entry.description} $keywords $localTerms".lowercase(Locale.ROOT)

            val fullDetail = buildString {
                append("${entry.code} - ${entry.description}")
                if (entry.keywords.isNotEmpty()) {
                    append(" [${entry.keywords.joinToString(", ")}]")
                }
                if (entry.localTerms.isNotEmpty()) {
                    val local = entry.localTerms.entries.joinToString("; ") { (lang, terms) ->
                        "$lang: ${terms.joinToString(", ")}"
                    }
                    append(" ($local)")
                }
            }

            allEntries.add(IndexedEntry(
                type = IndexedEntry.EntryType.ICD10,
                code = entry.code,
                name = entry.description,
                fullDetail = fullDetail,
                searchableText = searchable,
                vector = SparseVector.EMPTY // placeholder, computed below
            ))
        }

        // Index formulary drugs
        for (drug in formulary.drugs) {
            val aliases = drug.aliases.joinToString(" ")
            val searchable = "${drug.code} ${drug.name} $aliases ${drug.category} ${drug.defaultRoute}".lowercase(Locale.ROOT)

            val fullDetail = buildString {
                append("${drug.code} - ${drug.name}")
                if (drug.aliases.isNotEmpty()) {
                    append(" (${drug.aliases.joinToString(", ")})")
                }
                append(" [${drug.defaultRoute}]")
            }

            allEntries.add(IndexedEntry(
                type = IndexedEntry.EntryType.DRUG,
                code = drug.code,
                name = drug.name,
                fullDetail = fullDetail,
                searchableText = searchable,
                vector = SparseVector.EMPTY
            ))
        }

        // Build vocabulary from all searchable text
        val docFreq = mutableMapOf<String, Int>()
        val tokenized = allEntries.map { entry ->
            val tokens = tokenize(entry.searchableText)
            tokens.toSet().forEach { token ->
                docFreq[token] = (docFreq[token] ?: 0) + 1
            }
            tokens
        }

        // Filter vocabulary: keep tokens appearing in 2+ docs but <80% of docs (IDF filtering)
        val totalDocs = allEntries.size
        vocabulary = docFreq.entries
            .filter { it.value >= 2 && it.value < (totalDocs * 0.8).toInt() }
            .mapIndexed { index, entry -> entry.key to index }
            .toMap()

        val vocabSize = vocabulary.size

        // Build reverse index for O(1) lookup (avoids O(V^2) in IDF computation)
        val indexToTerm = Array(vocabSize) { "" }
        for ((term, idx) in vocabulary) {
            indexToTerm[idx] = term
        }

        // Compute IDF weights
        idfWeights = FloatArray(vocabSize) { idx ->
            val df = docFreq[indexToTerm[idx]] ?: 1
            kotlin.math.ln((totalDocs + 1f) / (df + 1f)) + 1f
        }

        // Compute sparse TF-IDF vectors for each entry
        entries = allEntries.mapIndexed { i, entry ->
            entry.copy(vector = computeSparseVector(tokenized[i]))
        }

        indexed = true
        Log.d(TAG, "Vector store indexed: ${entries.size} entries, vocabulary size: $vocabSize (sparse)")
    }

    // ── Retrieval ───────────────────────────────────────────────────────

    /**
     * Retrieve the top-K most relevant ICD-10 codes and drugs for a transcript.
     *
     * @param transcript The clinical transcript text
     * @param topKDiagnoses Max ICD-10 codes to retrieve (default 10)
     * @param topKDrugs Max formulary drugs to retrieve (default 15)
     * @return Pair of (matched ICD-10 entries, matched drug entries), sorted by relevance
     */
    fun retrieve(
        transcript: String,
        topKDiagnoses: Int = 10,
        topKDrugs: Int = 15
    ): RetrievalResult {
        if (!indexed) buildIndex()

        val queryVector = computeSparseVector(tokenize(transcript.lowercase(Locale.ROOT)))

        // Score all entries by cosine similarity (sparse dot product)
        val scored = entries.map { entry ->
            entry to sparseDot(queryVector, entry.vector)
        }

        val icd10Matches = scored
            .filter { it.first.type == IndexedEntry.EntryType.ICD10 && it.second > SIMILARITY_THRESHOLD }
            .sortedByDescending { it.second }
            .take(topKDiagnoses)
            .map { it.first }

        val drugMatches = scored
            .filter { it.first.type == IndexedEntry.EntryType.DRUG && it.second > SIMILARITY_THRESHOLD }
            .sortedByDescending { it.second }
            .take(topKDrugs)
            .map { it.first }

        Log.d(TAG, "Retrieved ${icd10Matches.size} ICD-10 codes + ${drugMatches.size} drugs for transcript (${transcript.length} chars)")

        return RetrievalResult(icd10Matches, drugMatches)
    }

    data class RetrievalResult(
        val icd10Entries: List<IndexedEntry>,
        val drugEntries: List<IndexedEntry>
    ) {
        val totalEntries get() = icd10Entries.size + drugEntries.size
    }

    // ── Sparse TF-IDF computation ────────────────────────────────────────

    private fun computeSparseVector(tokens: List<String>): SparseVector {
        if (vocabulary.isEmpty()) return SparseVector.EMPTY

        // Count term frequencies (only for tokens in our vocabulary)
        val tf = mutableMapOf<Int, Float>()
        val totalTokens = tokens.size.toFloat().coerceAtLeast(1f)
        for (token in tokens) {
            val idx = vocabulary[token] ?: continue
            tf[idx] = (tf[idx] ?: 0f) + 1f / totalTokens
        }
        if (tf.isEmpty()) return SparseVector.EMPTY

        // Compute TF-IDF and L2 norm in one pass
        val nonZero = mutableListOf<Pair<Int, Float>>()
        var normSq = 0.0
        for ((idx, tfVal) in tf) {
            val tfidf = tfVal * idfWeights[idx]
            if (tfidf > 0f) {
                nonZero.add(idx to tfidf)
                normSq += (tfidf * tfidf).toDouble()
            }
        }

        val norm = sqrt(normSq).toFloat()
        if (norm <= 0f) return SparseVector.EMPTY

        // Sort by index for efficient merge in sparseDot
        nonZero.sortBy { it.first }

        return SparseVector(
            indices = IntArray(nonZero.size) { nonZero[it].first },
            values = FloatArray(nonZero.size) { nonZero[it].second / norm }
        )
    }

    /**
     * Sparse dot product between two L2-normalized sparse vectors.
     * Uses sorted-merge for O(n+m) where n,m are the non-zero counts.
     */
    private fun sparseDot(a: SparseVector, b: SparseVector): Float {
        val aIdx = a.indices; val aVal = a.values
        val bIdx = b.indices; val bVal = b.values
        if (aIdx.isEmpty() || bIdx.isEmpty()) return 0f

        var dot = 0f
        var i = 0; var j = 0
        while (i < aIdx.size && j < bIdx.size) {
            when {
                aIdx[i] == bIdx[j] -> { dot += aVal[i] * bVal[j]; i++; j++ }
                aIdx[i] < bIdx[j] -> i++
                else -> j++
            }
        }
        return dot
    }

    /**
     * Simple clinical-aware tokenizer.
     * Splits on whitespace/punctuation, keeps alphanumeric tokens, handles ICD-10 codes.
     */
    private fun tokenize(text: String): List<String> {
        return text.split(TOKENIZE_REGEX)
            .map { it.trim('.', ':', '-', '"', '\'') }
            .filter { it.length >= 2 }
    }

    companion object {
        private const val TAG = "ClinicalVectorStore"
        /** Minimum cosine similarity to include in results. */
        private const val SIMILARITY_THRESHOLD = 0.05f
        /** Pre-compiled regex for tokenization — avoids recompilation per call (~0.5ms each). */
        private val TOKENIZE_REGEX = Regex("[\\s,;()\\[\\]{}]+")
    }
}
