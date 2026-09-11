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

$log = [System.IO.Path]::GetTempFileName()
$proc = Start-Process -FilePath $bin -RedirectStandardOutput $log -RedirectStandardError "$log.err" -PassThru -NoNewWindow
$proc.Id | Out-File -FilePath "$env:RUNNER_TEMP\testderp.pid"

$url = $null
for ($i = 0; $i -lt 100; $i++) {
	if (Test-Path $log) {
		$m = Select-String -Path $log -Pattern 'TAILCAT_DERPMAP_URL=(.*)' -ErrorAction SilentlyContinue | Select-Object -First 1
		if ($m) { $url = $m.Matches[0].Groups[1].Value; break }
	}
	Start-Sleep -Milliseconds 100
}

if (-not $url) {
	Write-Error "local DERP relay did not start in time"
	Get-Content $log, "$log.err" -ErrorAction SilentlyContinue
	exit 1
}

"TAILCAT_DERPMAP_URL=$url" | Out-File -Append -FilePath $env:GITHUB_ENV
Write-Host "local DERP relay ready: $url"
