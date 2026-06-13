package com.chartlite.benchmark

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.File
import java.io.FileOutputStream
import java.util.concurrent.TimeUnit
import java.util.zip.ZipFile

/**
 * Downloads model files from HuggingFace for each engine.
 */
object ModelDownloader {

    private const val TAG = "ModelDownloader"

    private val client = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(300, TimeUnit.SECONDS)
        .followRedirects(true)
        .build()

    data class Progress(val bytesDownloaded: Long, val totalBytes: Long) {
        val percent: Int get() = if (totalBytes > 0) ((bytesDownloaded * 100) / totalBytes).toInt() else 0
    }

    /**
     * Download a file from [url] to [destFile].
     * Calls [onProgress] periodically with download progress.
     * If [destFile] already exists with expected size, skips download.
     */
    suspend fun download(
        url: String,
        destFile: File,
        onProgress: (Progress) -> Unit = {}
    ): Boolean = withContext(Dispatchers.IO) {
        destFile.parentFile?.mkdirs()

        val request = Request.Builder().url(url).build()
        try {
            val response = client.newCall(request).execute()
            if (!response.isSuccessful) {
                Log.e(TAG, "Download failed: ${response.code} ${response.message}")
                return@withContext false
            }

            val body = response.body ?: return@withContext false
            val totalBytes = body.contentLength()
            var downloaded = 0L

            body.byteStream().use { input ->
                FileOutputStream(destFile).use { output ->
                    val buffer = ByteArray(8192)
                    var bytes: Int
                    while (input.read(buffer).also { bytes = it } != -1) {
                        output.write(buffer, 0, bytes)
                        downloaded += bytes
                        onProgress(Progress(downloaded, totalBytes))
                    }
                }
            }

            Log.i(TAG, "Downloaded ${destFile.name}: ${downloaded / 1024 / 1024}MB")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Download error", e)
            destFile.delete()
            false
        }
    }

    /**
     * Extract a zip file to [destDir]. Removes the zip after extraction.
     */
    suspend fun extractZip(zipFile: File, destDir: File): Boolean = withContext(Dispatchers.IO) {
        try {
            destDir.mkdirs()
            ZipFile(zipFile).use { zip ->
                for (entry in zip.entries()) {
                    val outFile = File(destDir, entry.name)
                    if (entry.isDirectory) {
                        outFile.mkdirs()
                        continue
                    }
                    outFile.parentFile?.mkdirs()
                    zip.getInputStream(entry).use { input ->
                        FileOutputStream(outFile).use { output ->
                            input.copyTo(output)
                        }
                    }
                }
            }
            zipFile.delete()
            Log.i(TAG, "Extracted to ${destDir.absolutePath}")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Extract error", e)
            false
        }
    }
}
