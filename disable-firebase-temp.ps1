$ErrorActionPreference = "Stop"

$File = "core\src\main\java\com\lyecdevelopers\core\utils\AppLogger.kt"

if (-not (Test-Path $File)) {
    Write-Host "No existe el archivo: $File"
    exit 1
}

Write-Host "==============================="
Write-Host "RESPALDANDO AppLogger.kt"
Write-Host "==============================="
Copy-Item $File "$File.bak" -Force

$content = Get-Content $File -Raw

# 1. Eliminar import de FirebaseCrashlytics
$content = $content -replace '(?m)^\s*import\s+com\.google\.firebase\.crashlytics\.FirebaseCrashlytics\s*\r?\n', ''

# 2. Asegurar import de android.util.Log
if ($content -notmatch 'import\s+android\.util\.Log') {
    $content = $content -replace '(?s)^(package[^\r\n]*\r?\n)', "`$1import android.util.Log`r`n"
}

# 3. Reemplazar recordException(...)
$content = $content -replace 'FirebaseCrashlytics\.getInstance\(\)\.recordException\(', 'Log.e("AppLogger", "Crashlytics disabled", '

# 4. Reemplazar log(...)
$content = $content -replace 'FirebaseCrashlytics\.getInstance\(\)\.log\(', 'Log.d("AppLogger", '

# 5. Reemplazar setCustomKey(...) por comentario/no-op
$content = $content -replace 'FirebaseCrashlytics\.getInstance\(\)\.setCustomKey\([^\)]*\)', 'Unit'

# 6. Reemplazar setUserId(...)
$content = $content -replace 'FirebaseCrashlytics\.getInstance\(\)\.setUserId\([^\)]*\)', 'Unit'

Set-Content $File $content -Encoding UTF8

Write-Host "AppLogger.kt fue parcheado temporalmente."
Write-Host "Backup guardado en: $File.bak"