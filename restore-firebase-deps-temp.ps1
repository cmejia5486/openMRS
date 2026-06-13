$ErrorActionPreference = "Stop"

$files = @(
    ".\app\build.gradle.kts",
    ".\auth\build.gradle.kts",
    ".\core\build.gradle.kts",
    ".\form\build.gradle.kts",
    ".\main\build.gradle.kts",
    ".\settings\build.gradle.kts",
    ".\sync\build.gradle.kts",
    ".\worklist\build.gradle.kts"
)

foreach ($file in $files) {
    if (-not (Test-Path $file)) {
        Write-Host "No existe: $file"
        continue
    }

    $content = Get-Content $file -Raw
    $original = $content

    $content = [regex]::Replace(
        $content,
        '(?m)^(\s*)//\s*(implementation\(platform\(libs\.firebase\.bom\)\))\s*$',
        '$1$2'
    )

    $content = [regex]::Replace(
        $content,
        '(?m)^(\s*)//\s*(implementation\(libs\.firebase\.analytics\))\s*$',
        '$1$2'
    )

    $content = [regex]::Replace(
        $content,
        '(?m)^(\s*)//\s*(implementation\(libs\.firebase\.crashlytics\))\s*$',
        '$1$2'
    )

    if ($content -ne $original) {
        Copy-Item $file "$file.bak-temp" -Force
        Set-Content -Path $file -Value $content -Encoding UTF8
        Write-Host "Restaurado: $file"
    } else {
        Write-Host "Sin cambios: $file"
    }
}

Write-Host ""
Write-Host "Proceso terminado."