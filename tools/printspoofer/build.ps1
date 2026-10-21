# 交叉/原生编译 PrintSpoofer.exe（Windows 目标）。-s -w 去除调试信息以缩小体积，
# 便于内嵌进 weshell 二进制后通过结构化写文件通道上传到靶机。
$ErrorActionPreference = 'Stop'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $dir
try {
    $env:GOOS   = 'windows'
    $env:GOARCH = 'amd64'
    go build -ldflags "-s -w" -o PrintSpoofer.exe .
    if ($LASTEXITCODE -ne 0) { throw 'go build failed' }
    Write-Host "Built PrintSpoofer.exe ($(Get-Location)\PrintSpoofer.exe)"
} finally {
    Pop-Location
}
