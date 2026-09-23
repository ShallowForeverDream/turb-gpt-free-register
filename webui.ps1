[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('start', 'stop', 'restart', 'status', 'logs')]
    [string]$Action = 'start',
    [string]$Python = '',
    [string]$EnvName = '',
    [string]$BindHost = '127.0.0.1',
    [ValidateRange(1, 65535)]
    [int]$Port = 5000,
    [ValidateRange(1, 120)]
    [int]$StartupTimeout = 30,
    [switch]$OpenBrowser
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$entry = Join-Path $root 'web.py'
$stateFile = Join-Path $root "run\webui-$Port.json"
$stdoutFile = Join-Path $root "logs\webui-$Port.log"
$stderrFile = Join-Path $root "logs\webui-$Port.error.log"

function Resolve-Python {
    if ($Python) {
        return (Get-Command $Python -CommandType Application -ErrorAction Stop).Source
    }
    if ($EnvName) {
        if (Test-Path -LiteralPath $EnvName -PathType Container) {
            return (Get-Item -LiteralPath (Join-Path $EnvName 'python.exe')).FullName
        }
        $info = (& conda env list --json | Out-String) | ConvertFrom-Json
        if ($LASTEXITCODE -ne 0) { throw 'Cannot list Conda environments.' }
        $candidateEnvs = @($info.envs | Where-Object { (Split-Path -Leaf $_) -eq $EnvName })
        if ($candidateEnvs.Count -ne 1) { throw "Conda environment is missing or ambiguous: $EnvName. Use -Python with an absolute path." }
        return (Get-Item -LiteralPath (Join-Path $candidateEnvs[0] 'python.exe')).FullName
    }
    $venv = Join-Path $root '.venv\Scripts\python.exe'
    if (Test-Path -LiteralPath $venv -PathType Leaf) { return $venv }
    return (Get-Command python -CommandType Application -ErrorAction Stop).Source
}

function Get-ManagedProcess {
    if (!(Test-Path -LiteralPath $stateFile)) { return $null }
    $state = Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json
    $process = Get-CimInstance Win32_Process -Filter "ProcessId = $([int]$state.ProcessId)"
    if (!$process) { return $null }
    # A PID can be reused. Require creation time, executable and this checkout's entrypoint.
    if ($process.CreationDate.ToUniversalTime().Ticks.ToString() -ne $state.StartedTicks -or
        $process.ExecutablePath -ne $state.Python -or
        !$process.CommandLine.Contains(('"' + $entry + '"'))) {
        throw 'Process identity no longer matches the saved state. No process was stopped. Inspect the state file before removing it.'
    }
    return $process
}

function Get-Listeners {
    return @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { $_.LocalPort -eq $Port })
}

function Stop-WebUI {
    $managed = Get-ManagedProcess
    if ($managed) {
        # Use a process handle and check its timestamp again before stopping it.
        $handle = Get-Process -Id $managed.ProcessId -ErrorAction Stop
        if ([Math]::Abs($handle.StartTime.ToUniversalTime().Ticks - $managed.CreationDate.ToUniversalTime().Ticks) -ge 10) {
            throw 'Process changed while checking its identity. Nothing was stopped.'
        }
        $handle.Kill()
        if (!$handle.WaitForExit(10000)) { throw 'WebUI did not exit within 10 seconds.' }
        Write-Output "Stopped WebUI PID=$($managed.ProcessId)."
    } else {
        Write-Output 'WebUI is not running.'
    }
    if (Test-Path -LiteralPath $stateFile) { Remove-Item -LiteralPath $stateFile }
}

function Start-WebUI {
    $address = $null
    if (![System.Net.IPAddress]::TryParse($BindHost, [ref]$address)) { throw '-BindHost must be an IP address.' }
    $urlHost = if ($BindHost -in @('0.0.0.0', '::')) { '127.0.0.1' } elseif ($BindHost.Contains(':')) { "[$BindHost]" } else { $BindHost }
    $url = "http://${urlHost}:$Port"
    $managed = Get-ManagedProcess
    if ($managed) {
        $state = Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json
        Write-Output "WebUI is already running: PID=$($managed.ProcessId), $($state.Url)"
        if ($OpenBrowser) { Start-Process $state.Url }
        return
    }
    if (@(Get-Listeners).Count) { throw "Port $Port is occupied. Choose another -Port; existing processes were left untouched." }
    $pythonExe = Resolve-Python
    if (!(Test-Path -LiteralPath $entry -PathType Leaf)) { throw "Missing entrypoint: $entry" }
    New-Item -ItemType Directory -Force -Path (Join-Path $root 'run'), (Join-Path $root 'logs') | Out-Null
    # -u flushes startup/errors immediately. Secrets stay in .env, not command-line arguments.
    $arguments = @('-u', ('"' + $entry + '"'), '--host', $BindHost, '--port', "$Port")
    $child = Start-Process -FilePath $pythonExe -ArgumentList $arguments -WorkingDirectory $root -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile
    $saved = $false
    try {
        $process = Get-CimInstance Win32_Process -Filter "ProcessId = $($child.Id)"
        if (!$process) { throw "WebUI exited during startup. See $stderrFile" }
        @{
            ProcessId = $child.Id
            StartedTicks = $process.CreationDate.ToUniversalTime().Ticks.ToString()
            Python = $process.ExecutablePath
            Url = $url
        } | ConvertTo-Json | Set-Content -LiteralPath $stateFile -Encoding UTF8
        $saved = $true
        $deadline = (Get-Date).AddSeconds($StartupTimeout)
        do {
            $child.Refresh()
            if ($child.HasExited) { throw "WebUI exited with code $($child.ExitCode). See $stderrFile" }
            if (@(Get-Listeners | Where-Object { $_.OwningProcess -eq $child.Id }).Count) {
                Write-Output "Started WebUI: PID=$($child.Id), $url"
                Write-Output "Logs: $stdoutFile and $stderrFile"
                if ($OpenBrowser) { Start-Process $url }
                return
            }
            Start-Sleep -Milliseconds 250
        } while ((Get-Date) -lt $deadline)
        throw "Startup timed out. See $stderrFile"
    } catch {
        if (!$child.HasExited) { $child.Kill(); $child.WaitForExit(10000) | Out-Null }
        if ($saved -and (Test-Path -LiteralPath $stateFile)) { Remove-Item -LiteralPath $stateFile }
        throw
    }
}

# Serialize management commands for this checkout and port.
$sha = [System.Security.Cryptography.SHA256]::Create()
$key = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes("$root|$Port"))).Replace('-', '')
$sha.Dispose()
$mutex = New-Object System.Threading.Mutex($false, "Local\TurbWebUI-$key")
$locked = $false
try {
    try { $locked = $mutex.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $locked = $true }
    if (!$locked) { throw 'Another management command is running for this checkout and port.' }
    switch ($Action) {
        'start' { Start-WebUI }
        'stop' { Stop-WebUI }
        'restart' { Stop-WebUI; Start-WebUI }
        'status' {
            $managed = Get-ManagedProcess
            if ($managed) { Write-Output "WebUI is running: PID=$($managed.ProcessId), port=$Port" }
            else { Write-Output 'WebUI is not running.' }
        }
        'logs' {
            foreach ($logPath in @($stdoutFile, $stderrFile)) {
                Write-Output $logPath
                if (Test-Path -LiteralPath $logPath) { Get-Content -LiteralPath $logPath -Tail 60 }
            }
        }
    }
} finally {
    if ($locked) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}
