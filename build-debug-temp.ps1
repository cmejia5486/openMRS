$ErrorActionPreference = "Stop"

Write-Host "==============================="
Write-Host "JAVA ACTIVO EN ESTA EJECUCION"
Write-Host "==============================="

$env:JAVA_HOME = "C:\Program Files\Java\jdk-17.1"
$env:Path = "$env:JAVA_HOME\bin;$env:Path"

Write-Host "JAVA_HOME = $env:JAVA_HOME"
java -version
Write-Host ""

Write-Host "==============================="
Write-Host "DETENIENDO DAEMONS ANTERIORES"
Write-Host "==============================="
& .\gradlew.bat '--stop'
Write-Host ""

Write-Host "==============================="
Write-Host "LIMPIANDO CARPETAS CONFLICTIVAS"
Write-Host "==============================="
$dirs = @(
    ".\build",
    ".\app\build",
    ".\core\build",
    ".\core-navigation\build"
)

foreach ($d in $dirs) {
    if (Test-Path $d) {
        try {
            Remove-Item $d -Recurse -Force
            Write-Host "Eliminado: $d"
        } catch {
            Write-Host "No se pudo eliminar: $d"
        }
    }
}
Write-Host ""

Write-Host "==============================="
Write-Host "VERIFICANDO GRADLE"
Write-Host "==============================="
& .\gradlew.bat '--version'
Write-Host ""

Write-Host "==============================="
Write-Host "GENERANDO DEBUG APK"
Write-Host "==============================="
& .\gradlew.bat ':app:assembleDebug' '--no-daemon' '--rerun-tasks' '-Pkotlin.incremental=false' '-Dkotlin.compiler.execution.strategy=in-process'
Write-Host ""

Write-Host "==============================="
Write-Host "BUSCANDO APK GENERADA"
Write-Host "==============================="
$apk = Get-ChildItem -Recurse ".\app\build\outputs\apk" -Filter *.apk -ErrorAction SilentlyContinue |
       Sort-Object LastWriteTime -Descending |
       Select-Object -First 1

if ($apk) {
    Write-Host "APK encontrada:"
    Write-Host $apk.FullName

    $destDir = ".\release-final"
    if (-not (Test-Path $destDir)) {
        New-Item -ItemType Directory -Path $destDir | Out-Null
    }

    $destFile = Join-Path $destDir "UgandaEMRMobile-debug.apk"
    Copy-Item $apk.FullName $destFile -Force

    Write-Host ""
    Write-Host "COPIA FINAL:"
    Write-Host (Resolve-Path $destFile)
} else {
    Write-Host "No se encontro ninguna APK debug."
}

Write-Host ""
Write-Host "==============================="
Write-Host "PROCESO TERMINADO"
Write-Host "==============================="