# End-to-end test of the Windows binaries.
#
# meowshell is a launcher only on Windows: tailcat there inherits the
# server's environment and picks PowerShell itself, so there is no shim to
# exercise. What this covers is that the binaries run, that a session can be
# opened over a tailcat address, and that a key given on stdin is staged and
# then cleaned up -- the one place the Windows path differs from Unix.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# PowerShell 7.3+ turns a non-zero exit from a native command into a
# terminating error under ErrorActionPreference 'Stop'. Several checks below
# deliberately run commands that are meant to fail, so opt out. Assigning it
# on older hosts where the variable does not exist is harmless.
$PSNativeCommandUseErrorActionPreference = $false

$dist      = if ($env:DIST) { $env:DIST } else { 'dist' }
$tailcat   = (Resolve-Path (Join-Path $dist 'tailcat_windows_amd64.exe')).Path
$meowshell = (Resolve-Path (Join-Path $dist 'meowshell_windows_amd64.exe')).Path
$marker    = "win-e2e-$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
$failed    = 0

function Pass($m) { Write-Host "ok    $m" }
function Fail($m) { Write-Host "FAIL  $m" -ForegroundColor Red; $script:failed = 1 }
function Assert-Match($desc, $pattern, $text) {
    if ($text -match $pattern) { Pass $desc } else { Fail "$desc (got: $text)" }
}

# The node key an address carries. A server picks a DERP region at startup
# and embeds it, so the address it publishes is not byte-identical to the
# one genkey printed; the identity inside is what has to match.
function Get-Identity($addr) {
    $json = (& $script:tailcat parse $addr | Out-String)
    if ($json -match '"ServerPublic":\s*"([^"]+)"') { return $Matches[1] }
    return ''
}

$work = Join-Path ([System.IO.Path]::GetTempPath()) "meowshell-e2e-$PID"
New-Item -ItemType Directory -Force -Path $work | Out-Null
$env:TAILCAT_BIN     = $tailcat
# Go's os.UserConfigDir reads %AppData% on Windows and ignores
# XDG_CONFIG_HOME, so genkey would otherwise write to the real profile and
# the key would not be where this script looks for it.
$env:APPDATA         = Join-Path $work 'config'
$env:XDG_CONFIG_HOME = Join-Path $work 'config'
$env:TMP             = $work
$env:TEMP            = $work

try {
    Write-Host '== 1. binaries run =='
    Assert-Match 'tailcat runs' '\S' (& $tailcat version | Out-String)
    $envOut = & $meowshell env | Out-String
    $envOut -split "`n" | ForEach-Object { if ($_.Trim()) { Write-Host "      $($_.TrimEnd())" } }
    Assert-Match 'meowshell found tailcat' 'tailcat\s+\w:' $envOut

    Write-Host '== 2. serve requires something to serve =='
    $noAuth = (& $meowshell serve 2>&1 | Out-String)
    Assert-Match 'serve refuses to run with nothing selected' 'choose what to serve' $noAuth
    $both = (& $meowshell serve --insecure-no-auth --authorized-keys=x 2>&1 | Out-String)
    Assert-Match 'the two auth modes are exclusive' 'mutually exclusive' $both

    Write-Host '== 3. a session over a tailcat address, key given on stdin =='
    $provisioned = (& $tailcat genkey --key=win-e2e | Select-Object -Last 1).Trim()
    # ::add-mask:: registers a value with the runner itself, so it gets
    # replaced with *** in this job's log from here on regardless of what
    # prints it later -- belt and suspenders alongside the inline redaction
    # above, which only covers print sites this script already knows about.
    Write-Host "::add-mask::$provisioned"
    $keyfile = Join-Path $env:APPDATA 'tailcat\keys\win-e2e.private.json'
    if (-not (Test-Path $keyfile)) { Fail "genkey did not write $keyfile"; exit 1 }
    Pass "provisioned a key ($($provisioned.Length) chars)"

    $addrFile = Join-Path $work 'addr'
    $env:TAILCAT_ADDR_FILE = $addrFile

    # Start-Process refuses a RedirectStandardInput path outright here, so
    # drive the process directly. stdout/stderr are captured rather than
    # left attached to the console, and redacted at capture time, since
    # the server's own diagnostics include the address it just published.
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $meowshell
    foreach ($a in @('serve', '--key-stdin', '--insecure-no-auth')) {
        $psi.ArgumentList.Add($a)
    }
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false

    $serverOutput = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
    $server = [System.Diagnostics.Process]::new()
    $server.StartInfo = $psi
    # Redacted inline, not via a script-scope function: Register-ObjectEvent's
    # -Action block does not reliably see functions defined outside it, so
    # this stays self-contained rather than risk a silent no-op.
    $onLine = {
        if ($null -ne $Event.SourceEventArgs.Data) {
            $Event.MessageData.Enqueue(($Event.SourceEventArgs.Data -replace 'tc[A-Za-z0-9_-]{10,}', 'tc<redacted>'))
        }
    }
    $outSub = Register-ObjectEvent -InputObject $server -EventName OutputDataReceived -Action $onLine -MessageData $serverOutput
    $errSub = Register-ObjectEvent -InputObject $server -EventName ErrorDataReceived -Action $onLine -MessageData $serverOutput
    $server.Start() | Out-Null
    $server.BeginOutputReadLine()
    $server.BeginErrorReadLine()
    $server.StandardInput.Write((Get-Content $keyfile -Raw))
    $server.StandardInput.Close()

    $addr = $null
    foreach ($i in 1..40) {
        if ((Test-Path $addrFile) -and (Get-Item $addrFile).Length -gt 0) {
            $addr = (Get-Content $addrFile -Raw).Trim(); break
        }
        if ($server.HasExited) { break }
        Start-Sleep -Seconds 2
    }

    if (-not $addr) {
        Fail 'server published no address (redacted server output below)'
        $serverOutput.ToArray() | ForEach-Object { Write-Host "      $_" }
    } else {
        Write-Host "::add-mask::$addr"
        Pass 'server published an address'
        if ((Get-Identity $addr) -eq (Get-Identity $provisioned) -and (Get-Identity $addr)) {
            Pass 'the published address carries the provisioned identity'
        } else {
            Fail 'published address is a different identity from the provisioned one'
        }

        $out = (& $tailcat ssh $addr "echo $marker" 2>&1 | Out-String)
        $out -split "`n" | Select-Object -First 6 | ForEach-Object {
            if ($_.Trim()) { Write-Host "      $($_.TrimEnd())" }
        }
        Assert-Match 'remote command ran on this machine' $marker $out
    }

    if ($server -and -not $server.HasExited) { $server.Kill(); $server.WaitForExit(5000) | Out-Null }

    # Windows cannot unlink an open file, so the key is a real file while
    # tailcat runs and is removed once it exits. Nothing may be left behind.
    $left = @(Get-ChildItem -Path $work -Filter 'meowshell-key-*' -ErrorAction SilentlyContinue)
    if ($left.Count -eq 0) {
        Pass 'the staged key was cleaned up'
    } else {
        Fail "$($left.Count) staged key file(s) left behind"
    }
} finally {
    if ($outSub) { Unregister-Event -SourceIdentifier $outSub.Name -ErrorAction SilentlyContinue }
    if ($errSub) { Unregister-Event -SourceIdentifier $errSub.Name -ErrorAction SilentlyContinue }
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}

Write-Host ''
if ($failed -eq 0) { Write-Host 'all Windows checks passed' } else { Write-Host 'Windows checks failed' }
exit $failed
