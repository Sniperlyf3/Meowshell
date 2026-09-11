# Windows equivalent of start-testderp.sh: starts e2e/testderp (a single-node,
# loopback-only DERP relay) in the background and exports TAILCAT_DERPMAP_URL
# for the rest of this job, so E2E tests never depend on reaching the public
# Tailscale relay infrastructure. See start-testderp.sh for the full
# rationale; both scripts exist because the two OSes need different
# background-process and env-file mechanics, not different behavior.
$ErrorActionPreference = "Stop"

$bin = [System.IO.Path]::GetTempFileName() + ".exe"
& go build -o $bin ./e2e/testderp
if ($LASTEXITCODE -ne 0) { throw "go build ./e2e/testderp failed" }

# Start-Process's child belongs to the runner's Job Object for this step and
# is killed the moment this step's shell exits -- so it would never survive
# to the "End-to-end test on Windows" step that actually needs it. Launching
# through WMI/CIM instead makes wmiprvse.exe the parent, outside that Job
# Object, so the relay survives the step boundary. That also means there is
# no stdout pipe back to us the way Start-Process would give one, hence
# -status-file instead of watching redirected output.
$status = [System.IO.Path]::GetTempFileName()
$commandLine = "`"$bin`" -status-file `"$status`""
$result = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $commandLine }
if ($result.ReturnValue -ne 0) { throw "Win32_Process.Create failed with code $($result.ReturnValue)" }
$result.ProcessId | Out-File -FilePath "$env:RUNNER_TEMP\testderp.pid"

$url = $null
for ($i = 0; $i -lt 100; $i++) {
	if ((Test-Path $status) -and (Get-Item $status).Length -gt 0) {
		$m = Select-String -Path $status -Pattern 'TAILCAT_DERPMAP_URL=(.*)' -ErrorAction SilentlyContinue | Select-Object -First 1
		if ($m) { $url = $m.Matches[0].Groups[1].Value; break }
	}
	Start-Sleep -Milliseconds 100
}

if (-not $url) {
	Write-Error "local DERP relay did not start in time"
	exit 1
}

"TAILCAT_DERPMAP_URL=$url" | Out-File -Append -FilePath $env:GITHUB_ENV
Write-Host "local DERP relay ready: $url"
