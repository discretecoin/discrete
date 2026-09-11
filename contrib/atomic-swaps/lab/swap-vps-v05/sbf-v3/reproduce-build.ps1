param(
    [string]$ToolsRoot = (Join-Path $PSScriptRoot '../../swap-integration-v03/external-tools/platform-tools'),
    [string]$RunName = 'target-repro-01'
)
$ErrorActionPreference = 'Stop'
if ($RunName -notmatch '^target-repro-[a-zA-Z0-9-]+$') { throw 'RunName must name a new target-repro-* child directory.' }
$runRoot = Join-Path $PSScriptRoot $RunName
if (Test-Path -LiteralPath $runRoot) { throw 'Use a fresh RunName; previous build evidence is never overwritten.' }
$toolsAbsolute = (Resolve-Path -LiteralPath $ToolsRoot).Path
$expectedInputs = @{
    'src/lib.rs' = '6fa662506bd667f6e510aaa3ea9aea74edaadeebdc829bd82bcfc05325b60eea'
    'Cargo.toml' = '95fbea4c3925ab8043baa328dd2bdc0509883841474ee8c811af10356e02e965'
    'Cargo.lock' = 'ecb88b8469a190be6c5587f4762eaef619f4e8bdaaa45171821f6ea4c41f2102'
}
foreach ($item in $expectedInputs.GetEnumerator()) {
    $actual = (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $item.Key) -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $item.Value) { throw "Frozen input mismatch: $($item.Key)" }
}
$cargo = Join-Path $toolsAbsolute 'rust/bin/cargo.exe'
$rustc = Join-Path $toolsAbsolute 'rust/bin/rustc.exe'
$linker = Join-Path $toolsAbsolute 'rust/lib/rustlib/x86_64-pc-windows-msvc/bin/rust-lld.exe'
$readelf = Join-Path $toolsAbsolute 'llvm/bin/llvm-readelf.exe'
$toolHashes = @{}
foreach ($path in @($cargo, $rustc, $linker, $readelf)) {
    $toolHashes[$path] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
}
$oldEnv = @{}
foreach ($name in @('CARGO_HOME', 'RUSTC', 'CARGO_BUILD_JOBS', 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS')) {
    $oldEnv[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
New-Item -ItemType Directory -Path $runRoot | Out-Null
Push-Location $PSScriptRoot
try {
    # Keep the original command's forward-slash spelling: Rust embeds dependency
    # source paths in panic locations, so changing slash spelling changes the ELF.
    $env:CARGO_HOME = (Join-Path $PSScriptRoot 'cargo-home').Replace('\', '/')
    $env:RUSTC = $rustc.Replace('\', '/')
    $env:CARGO_BUILD_JOBS = '1'
    $env:RUSTFLAGS = ''
    $env:CARGO_ENCODED_RUSTFLAGS = ''
    $compilerVersion = (& $rustc --version --verbose | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'rustc version failed.' }
    $cargoVersion = (& $cargo --version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'cargo version failed.' }
    $started = [DateTime]::UtcNow.ToString('o')
    $buildArgs = @('build', '--offline', '--locked', '--target', 'sbpfv3-solana-solana', '--release', '--target-dir', $runRoot)
    & $cargo @buildArgs 2>&1 | Tee-Object -FilePath (Join-Path $runRoot 'build.log')
    if ($LASTEXITCODE -ne 0) { throw "Cargo build failed: $LASTEXITCODE" }
    $artifact = Join-Path $runRoot 'sbpfv3-solana-solana/release/xds_swap_sbpfv3.so'
    $artifactHash = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
    $candidateHash = (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'solana_escrow.so') -Algorithm SHA256).Hash.ToLowerInvariant()
    & $readelf -h -l -s $artifact 2>&1 | Set-Content -LiteralPath (Join-Path $runRoot 'elf-inspection.log') -Encoding utf8
    if ($LASTEXITCODE -ne 0) { throw 'ELF inspection failed.' }
    $result = [ordered]@{
        startedUtc = $started
        finishedUtc = [DateTime]::UtcNow.ToString('o')
        platformTools = '1.57'
        commandExecutable = $cargo
        commandArguments = $buildArgs
        compilerVersion = $compilerVersion
        cargoVersion = $cargoVersion
        toolSha256 = $toolHashes
        inputSha256 = $expectedInputs
        buildJobs = 1
        cargoHome = $env:CARGO_HOME
        artifact = $artifact
        artifactBytes = (Get-Item -LiteralPath $artifact).Length
        artifactSha256 = $artifactHash
        candidateSha256 = $candidateHash
        identicalToCandidate = ($artifactHash -eq $candidateHash)
        scope = 'Second local build with a fresh target directory and the same locked source/toolchain; no cross-host reproducibility or RPC claim.'
    }
    $result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $runRoot 'result.json') -Encoding utf8
    if ($artifactHash -ne $candidateHash -or $artifactHash -ne '30c22daccdd194896ddec53543410b1163c27fea378a58942c018033820f50b7') {
        throw 'Fresh build differs from the candidate; inspect result.json.'
    }
    Write-Output "PASS: fresh target build produced identical SHA256 $artifactHash"
}
finally {
    Pop-Location
    foreach ($name in $oldEnv.Keys) { [Environment]::SetEnvironmentVariable($name, $oldEnv[$name], 'Process') }
}
