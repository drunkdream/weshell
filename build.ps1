# weshell 整体构建：先编译内嵌用的 PrintSpoofer.exe，再编译 weshell 服务本身
# （//go:embed 需要 tools/printspoofer/PrintSpoofer.exe 在构建时已存在）。
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $root
try {
    Write-Host "==> 构建内嵌工具 PrintSpoofer.exe"
    & "$root\tools\printspoofer\build.ps1"
    if ($LASTEXITCODE -ne 0) { throw 'PrintSpoofer 构建失败' }

    Write-Host "==> 构建 weshell.exe"
    go build -o weshell.exe .
    if ($LASTEXITCODE -ne 0) { throw 'weshell 构建失败' }
    Write-Host "完成: $root\weshell.exe"
} finally {
    Pop-Location
}
