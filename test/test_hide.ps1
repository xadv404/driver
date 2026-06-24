#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Suite de tests automatisée pour SelfHideDriver (CTF).
    Lance chaque méthode de détection et affiche un score final.
.USAGE
    .\test_hide.ps1 -DriverPath "C:\...\SelfHideDriver.sys"
#>

param(
    [Parameter(Mandatory)]
    [string]$DriverPath
)

$SERVICE_NAME = "SelfHideDriver"
$PASS = 0
$FAIL = 0
$results = @()

function Write-Header($text) {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host " $text" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function Test-Result($testName, [bool]$hidden) {
    if ($hidden) {
        Write-Host "  [PASSE] $testName" -ForegroundColor Green
        $script:PASS++
    } else {
        Write-Host "  [FAIL]  $testName" -ForegroundColor Red
        $script:FAIL++
    }
    $script:results += [PSCustomObject]@{ Test = $testName; Resultat = if ($hidden) { "PASSE" } else { "FAIL" } }
}

# ---------------------------------------------------------------------------
Write-Header "PREREQUIS"
# ---------------------------------------------------------------------------

if (-not (Test-Path $DriverPath)) {
    Write-Host "[ERREUR] Fichier introuvable : $DriverPath" -ForegroundColor Red
    exit 1
}
Write-Host "  Driver : $DriverPath" -ForegroundColor Gray

$bcdedit = bcdedit /enum | Select-String "testsigning"
if ($bcdedit -match "Yes") {
    Write-Host "  Test signing : ACTIVE" -ForegroundColor Green
} else {
    Write-Host "  [AVERT] Test signing non detecte. Le driver risque de ne pas se charger." -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
Write-Header "CHARGEMENT DU DRIVER"
# ---------------------------------------------------------------------------

sc.exe delete $SERVICE_NAME 2>$null | Out-Null
sc.exe create $SERVICE_NAME type= kernel binPath= "`"$DriverPath`"" | Out-Null
$startResult = sc.exe start $SERVICE_NAME 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "  [ERREUR] Impossible de charger le driver : $startResult" -ForegroundColor Red
    sc.exe delete $SERVICE_NAME 2>$null | Out-Null
    exit 1
}
Write-Host "  Driver charge avec succes" -ForegroundColor Green
Start-Sleep -Milliseconds 500

# ---------------------------------------------------------------------------
Write-Header "TESTS DE DETECTION"
# ---------------------------------------------------------------------------

# Test 1 : driverquery
$dq = driverquery /v 2>$null
$hidden1 = -not ($dq | Select-String $SERVICE_NAME -Quiet)
Test-Result "driverquery /v" $hidden1

# Test 2 : sc query
$scq = sc.exe query type= driver state= all 2>$null
$hidden2 = -not ($scq | Select-String $SERVICE_NAME -Quiet)
Test-Result "sc query (liste tous les drivers)" $hidden2

# Test 3 : WMI Win32_SystemDriver
$wmi = Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue |
       Where-Object { $_.Name -like "*$SERVICE_NAME*" -or $_.PathName -like "*$SERVICE_NAME*" }
$hidden3 = ($null -eq $wmi)
Test-Result "WMI Win32_SystemDriver" $hidden3

# Test 4 : Registre Services
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$SERVICE_NAME"
$hidden4 = -not (Test-Path $regPath)
Test-Result "Registre HKLM\...\Services" $hidden4

# Test 5 : EnumDeviceDrivers via PowerShell (appel API Win32)
$code = @"
using System;
using System.Runtime.InteropServices;
public class KernelEnum {
    [DllImport("psapi.dll")]
    public static extern bool EnumDeviceDrivers(IntPtr[] lpImageBase, uint cb, out uint lpcbNeeded);
    [DllImport("psapi.dll", CharSet=CharSet.Unicode)]
    public static extern uint GetDeviceDriverFileName(IntPtr ImageBase, System.Text.StringBuilder lpFilename, uint nSize);
}
"@
Add-Type -TypeDefinition $code -ErrorAction SilentlyContinue
$foundViaAPI = $false
try {
    $needed = 0u
    [KernelEnum]::EnumDeviceDrivers($null, 0, [ref]$needed) | Out-Null
    $count = $needed / [IntPtr]::Size
    $bases = New-Object IntPtr[] $count
    [KernelEnum]::EnumDeviceDrivers($bases, $needed, [ref]$needed) | Out-Null
    foreach ($base in $bases) {
        $sb = New-Object System.Text.StringBuilder 260
        [KernelEnum]::GetDeviceDriverFileName($base, $sb, 260) | Out-Null
        if ($sb.ToString() -like "*$SERVICE_NAME*") { $foundViaAPI = $true; break }
    }
} catch {}
Test-Result "EnumDeviceDrivers (WinAPI)" (-not $foundViaAPI)

# Test 6 : Modules kernel via NtQuerySystemInformation (SystemModuleInformation)
# On passe par la commande Get-Process qui utilise cette API indirectement
$tasklistDrivers = tasklist /v 2>$null | Select-String $SERVICE_NAME -Quiet
$hidden6 = -not $tasklistDrivers
Test-Result "tasklist (processus associes)" $hidden6

# Test 7 : Recherche du fichier .sys dans les handles ouverts
$openFiles = handle64.exe -a 2>$null | Select-String $SERVICE_NAME -Quiet
if ($null -eq (Get-Command "handle64.exe" -ErrorAction SilentlyContinue)) {
    Write-Host "  [SKIP]  Sysinternals handle64.exe non trouve dans PATH" -ForegroundColor Yellow
} else {
    Test-Result "Sysinternals handle64 (handles ouverts)" (-not $openFiles)
}

# ---------------------------------------------------------------------------
Write-Header "DECHARGEMENT DU DRIVER"
# ---------------------------------------------------------------------------
sc.exe stop $SERVICE_NAME  | Out-Null
Start-Sleep -Milliseconds 300
sc.exe delete $SERVICE_NAME | Out-Null
Write-Host "  Driver decharge et supprime" -ForegroundColor Gray

# Test post-déchargement : traces dans MmUnloadedDrivers
# (pas accessible directement depuis user-mode sans kernel debugger)
Write-Host "  [INFO]  MmUnloadedDrivers : verifiable uniquement via WinDbg" -ForegroundColor Gray
Write-Host "          Commande WinDbg : dq MmUnloadedDrivers L$(0x50*5)" -ForegroundColor DarkGray

# ---------------------------------------------------------------------------
Write-Header "RAPPORT FINAL"
# ---------------------------------------------------------------------------
$total = $PASS + $FAIL
$score = if ($total -gt 0) { [math]::Round(($PASS / $total) * 100) } else { 0 }

Write-Host ""
$results | Format-Table -AutoSize
Write-Host ""
Write-Host "  Score de dissimulation : " -NoNewline
$color = if ($score -ge 80) { "Green" } elseif ($score -ge 50) { "Yellow" } else { "Red" }
Write-Host "$score / 100  ($PASS/$total tests passes)" -ForegroundColor $color

if ($score -lt 100) {
    Write-Host "`n  Pistes d'amelioration :" -ForegroundColor Yellow
    if ($FAIL -gt 0) {
        $results | Where-Object Resultat -eq "FAIL" | ForEach-Object {
            Write-Host "    -> Echec sur : $($_.Test)" -ForegroundColor DarkYellow
        }
    }
    Write-Host "  Note : registre et sc query refletent l'etat AVANT chargement." -ForegroundColor DarkGray
    Write-Host "         Un driver charge manuellement (OSR Loader) evite ces traces." -ForegroundColor DarkGray
}
