param(
    [switch]$SkipBrowserOpen,
    [switch]$OpenDemoProfiles
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$WorkRoot = Split-Path -Parent $RepoRoot
$Python = Join-Path $WorkRoot ".venv-postquantum\Scripts\python.exe"
$LogRoot = Join-Path $WorkRoot "runtime-logs"
$Apache = "C:\Apache24\bin\httpd.exe"
$ApacheConf = "C:\Apache24\conf\httpd.conf"
$Domain = "thanhthuydepgai.42web.io"
$DemoProfileRoot = Join-Path $WorkRoot "demo-browser-profiles"

New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null

function Test-ListenPort {
    param([int]$Port)
    $conn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    return $null -ne $conn
}

function Start-HiddenPowerShell {
    param(
        [string]$Name,
        [string]$WorkingDirectory,
        [string]$Command
    )

    $stdout = Join-Path $LogRoot "$Name.out.log"
    $stderr = Join-Path $LogRoot "$Name.err.log"
    $wrapped = "& { Set-Location -LiteralPath '$WorkingDirectory'; $Command }"

    $process = Start-Process `
        -FilePath "powershell.exe" `
        -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", $wrapped) `
        -WindowStyle Hidden `
        -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr `
        -PassThru

    Write-Host "[OK] Started $Name (PID $($process.Id))"
    Write-Host "     logs: $stdout"
}

function Get-ChromePath {
    $candidates = @(
        "C:\Program Files\Google\Chrome\Application\chrome.exe",
        "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        (Join-Path $env:LOCALAPPDATA "Google\Chrome\Application\chrome.exe"),
        "C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
    )
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path $candidate)) {
            return $candidate
        }
    }
    return $null
}

function Open-DemoBrowserProfile {
    param(
        [string]$Role,
        [string]$Url
    )

    $browser = Get-ChromePath
    if (-not $browser) {
        Write-Host "[WARN] Chrome/Edge executable not found; opening default browser for $Role"
        Start-Process $Url
        return
    }

    $profilePath = Join-Path $DemoProfileRoot $Role
    New-Item -ItemType Directory -Path $profilePath -Force | Out-Null
    Start-Process `
        -FilePath $browser `
        -ArgumentList @("--user-data-dir=$profilePath", "--new-window", $Url)
    Write-Host "[OK] Opened $Role browser profile: $profilePath"
}

if (-not (Test-Path $Python)) {
    throw "Python venv not found: $Python"
}
if (-not (Test-Path $Apache)) {
    throw "Apache not found: $Apache"
}

$env:PUBLIC_PORTAL_DOMAIN = $Domain
$env:PUBLIC_PORTAL_ORIGIN = "https://$Domain"
$env:DJANGO_ALLOWED_HOSTS = "$Domain,localhost,127.0.0.1,[::1]"
$env:DJANGO_CSRF_TRUSTED_ORIGINS = "https://$Domain"
$env:DJANGO_DEBUG = "true"
$env:DJANGO_SESSION_COOKIE_SECURE = "false"
$env:DJANGO_CSRF_COOKIE_SECURE = "false"
$env:DJANGO_SECURE_SSL_REDIRECT = "false"
$env:CA_SERVICE_URL = "http://127.0.0.1:5001"
$env:LOCAL_AGENT_URL = "http://127.0.0.1:54321"
$env:AGENT_ALLOWED_ORIGIN_REGEX = "https?://(localhost|127\.0\.0\.1|$($Domain.Replace('.', '\.')))(:\d+)?"
$env:OFFICER_DEVICE_PROOF_TTL_SECONDS = "900"
$env:PRIVATE_BLOB_STORAGE_ROOT = Join-Path $RepoRoot "CA-KMS Server\private_storage"

Write-Host "== Starting PostQuantum local demo =="
Write-Host "Domain: https://$Domain"
Write-Host "Repo:   $RepoRoot"

Write-Host "== Seeding RA demo admin =="
Push-Location (Join-Path $RepoRoot "PublicAdminWeb")
try {
    & $Python "manage.py" seed_demo_admin
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[WARN] Could not seed demo admin; continue starting services"
    }
} finally {
    Pop-Location
}

if (-not (Test-ListenPort 5001)) {
    Start-HiddenPowerShell `
        -Name "ca-ra-tsa-5001" `
        -WorkingDirectory (Join-Path $RepoRoot "CA-KMS Server") `
        -Command "`$env:PRIVATE_BLOB_STORAGE_ROOT='$($env:PRIVATE_BLOB_STORAGE_ROOT)'; & '$Python' -u 'main.py'"
} else {
    Write-Host "[SKIP] CA/RA/TSA already listens on 5001"
}

if (-not (Test-ListenPort 54321)) {
    Start-HiddenPowerShell `
        -Name "pqc-agent-54321" `
        -WorkingDirectory (Join-Path $RepoRoot "pqc_agent") `
        -Command "`$env:PUBLIC_PORTAL_ORIGIN='https://$Domain'; `$env:AGENT_ALLOWED_ORIGIN_REGEX='$($env:AGENT_ALLOWED_ORIGIN_REGEX)'; & '$Python' -u 'pqc_agent.py'"
} else {
    Write-Host "[SKIP] PQC Local Agent already listens on 54321"
}

if (-not (Test-ListenPort 8000)) {
    Start-HiddenPowerShell `
        -Name "django-portal-8000" `
        -WorkingDirectory (Join-Path $RepoRoot "PublicAdminWeb") `
        -Command "`$env:PUBLIC_PORTAL_DOMAIN='$Domain'; `$env:PUBLIC_PORTAL_ORIGIN='https://$Domain'; `$env:DJANGO_ALLOWED_HOSTS='$($env:DJANGO_ALLOWED_HOSTS)'; `$env:DJANGO_CSRF_TRUSTED_ORIGINS='$($env:DJANGO_CSRF_TRUSTED_ORIGINS)'; `$env:DJANGO_DEBUG='true'; `$env:DJANGO_SESSION_COOKIE_SECURE='false'; `$env:DJANGO_CSRF_COOKIE_SECURE='false'; `$env:DJANGO_SECURE_SSL_REDIRECT='false'; `$env:CA_SERVICE_URL='http://127.0.0.1:5001'; `$env:LOCAL_AGENT_URL='http://127.0.0.1:54321'; & '$Python' -u 'manage.py' runserver 127.0.0.1:8000 --noreload"
} else {
    Write-Host "[SKIP] Django portal already listens on 8000"
}

if (-not (Test-ListenPort 443)) {
    Write-Host "[INFO] Checking Apache config..."
    & $Apache -t -f $ApacheConf
    if ($LASTEXITCODE -ne 0) {
        throw "Apache config test failed."
    }

    Start-Process `
        -FilePath $Apache `
        -ArgumentList @("-f", $ApacheConf) `
        -WindowStyle Hidden `
        -WorkingDirectory "C:\Apache24" `
        -PassThru | Out-Null

    Write-Host "[OK] Started Apache HTTPS reverse proxy on 443"
} else {
    Write-Host "[SKIP] Apache/HTTPS already listens on 443"
}

Start-Sleep -Seconds 4

Write-Host ""
Write-Host "== Port check =="
foreach ($port in 5001, 54321, 8000, 443) {
    if (Test-ListenPort $port) {
        Write-Host "[OK] Port $port is listening"
    } else {
        Write-Host "[FAIL] Port $port is NOT listening"
    }
}

Write-Host ""
Write-Host "== TLS check command =="
Write-Host "echo Q | openssl s_client -connect ${Domain}:443 -servername ${Domain} -tls1_3 -brief -CAfile C:\Apache24\conf\ssl\postquantum-thanhthuydepgai\ca_bundle.crt -partial_chain"

if (-not $SkipBrowserOpen) {
    if ($OpenDemoProfiles) {
        Open-DemoBrowserProfile -Role "citizen" -Url "https://$Domain/login/"
        Open-DemoBrowserProfile -Role "officer" -Url "https://$Domain/login/"
        Open-DemoBrowserProfile -Role "admin" -Url "https://$Domain/login/"
    } else {
        Start-Process "https://$Domain/"
    }
}
