#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Suite de tests anti-detection pour SelfHideDriver (CTF).
    Simule les methodes utilisees par les anti-cheats (EAC, BE, Vanguard).
.USAGE
    .\test_hide.ps1 -DriverPath "C:\...\SelfHideDriver.sys" [-KdmapperMode]
#>

param(
    [Parameter(Mandatory)]
    [string]$DriverPath,
    [switch]$KdmapperMode   # Active si le driver est charge via kdmapper
)

$SERVICE_NAME = "SelfHideDriver"
$PASS = 0; $FAIL = 0; $SKIP = 0
$results = @()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Header($t) {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host " $t" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function Add-Result($name, [bool]$hidden, [bool]$skipped = $false) {
    if ($skipped) {
        Write-Host "  [SKIP]  $name" -ForegroundColor Yellow
        $script:SKIP++
        $script:results += [PSCustomObject]@{ Test = $name; Resultat = "SKIP" }
    } elseif ($hidden) {
        Write-Host "  [PASSE] $name" -ForegroundColor Green
        $script:PASS++
        $script:results += [PSCustomObject]@{ Test = $name; Resultat = "PASSE" }
    } else {
        Write-Host "  [FAIL]  $name" -ForegroundColor Red
        $script:FAIL++
        $script:results += [PSCustomObject]@{ Test = $name; Resultat = "FAIL" }
    }
}

# ---------------------------------------------------------------------------
# Types P/Invoke partages
# ---------------------------------------------------------------------------
$nativeCode = @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public class NativeAPI {
    // --- NtQuerySystemInformation ---
    [DllImport("ntdll.dll")]
    public static extern int NtQuerySystemInformation(
        int SystemInformationClass,
        IntPtr SystemInformation,
        uint SystemInformationLength,
        out uint ReturnLength);

    // --- EnumDeviceDrivers ---
    [DllImport("psapi.dll")]
    public static extern bool EnumDeviceDrivers(IntPtr[] lpImageBase, uint cb, out uint lpcbNeeded);
    [DllImport("psapi.dll", CharSet=CharSet.Unicode)]
    public static extern uint GetDeviceDriverFileName(IntPtr ImageBase, StringBuilder lpFilename, uint nSize);

    // --- Object Manager ---
    [DllImport("ntdll.dll")]
    public static extern int NtOpenDirectoryObject(
        out IntPtr DirectoryHandle,
        uint DesiredAccess,
        ref OBJECT_ATTRIBUTES ObjectAttributes);

    [DllImport("ntdll.dll")]
    public static extern int NtQueryDirectoryObject(
        IntPtr DirectoryHandle,
        IntPtr Buffer,
        uint Length,
        bool ReturnSingleEntry,
        bool RestartScan,
        ref uint Context,
        out uint ReturnLength);

    [DllImport("ntdll.dll")]
    public static extern int RtlInitUnicodeString(ref UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString);

    [DllImport("kernel32.dll")]
    public static extern IntPtr LocalAlloc(uint uFlags, IntPtr uBytes);
    [DllImport("kernel32.dll")]
    public static extern IntPtr LocalFree(IntPtr hMem);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);
}

[StructLayout(LayoutKind.Sequential)]
public struct RTL_PROCESS_MODULE_INFORMATION {
    public IntPtr Section;
    public IntPtr MappedBase;
    public IntPtr ImageBase;
    public uint ImageSize;
    public uint Flags;
    public ushort LoadOrderIndex;
    public ushort InitOrderIndex;
    public ushort LoadCount;
    public ushort OffsetToFileName;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst=256)]
    public byte[] FullPathName;
}

[StructLayout(LayoutKind.Sequential)]
public struct UNICODE_STRING {
    public ushort Length;
    public ushort MaximumLength;
    public IntPtr Buffer;
}

[StructLayout(LayoutKind.Sequential)]
public struct OBJECT_ATTRIBUTES {
    public uint Length;
    public IntPtr RootDirectory;
    public IntPtr ObjectName;
    public uint Attributes;
    public IntPtr SecurityDescriptor;
    public IntPtr SecurityQualityOfService;
}

[StructLayout(LayoutKind.Sequential)]
public struct OBJECT_DIRECTORY_INFORMATION {
    public UNICODE_STRING Name;
    public UNICODE_STRING TypeName;
}
"@

Add-Type -TypeDefinition $nativeCode -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# PREREQUIS
# ---------------------------------------------------------------------------
Write-Header "PREREQUIS"

if (-not (Test-Path $DriverPath)) {
    Write-Host "[ERREUR] Fichier introuvable : $DriverPath" -ForegroundColor Red; exit 1
}
Write-Host "  Driver     : $DriverPath" -ForegroundColor Gray
Write-Host "  Mode       : $(if ($KdmapperMode) { 'kdmapper' } else { 'sc/NtLoadDriver' })" -ForegroundColor Gray

$bcdedit = bcdedit /enum | Select-String "testsigning"
if ($bcdedit -match "Yes") { Write-Host "  TestSigning: ACTIVE" -ForegroundColor Green }
else { Write-Host "  [AVERT] TestSigning desactive (kdmapper le contourne, mais sc ne marchera pas)" -ForegroundColor Yellow }

# ---------------------------------------------------------------------------
# CHARGEMENT
# ---------------------------------------------------------------------------
Write-Header "CHARGEMENT DU DRIVER"

if (-not $KdmapperMode) {
    sc.exe delete $SERVICE_NAME 2>$null | Out-Null
    sc.exe create $SERVICE_NAME type= kernel binPath= "`"$DriverPath`"" | Out-Null
    $r = sc.exe start $SERVICE_NAME 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  [ERREUR] $r" -ForegroundColor Red
        sc.exe delete $SERVICE_NAME 2>$null | Out-Null; exit 1
    }
    Write-Host "  Charge via sc.exe" -ForegroundColor Green
} else {
    Write-Host "  [INFO] Mode kdmapper : charge manuellement le driver AVANT de lancer ce script" -ForegroundColor Yellow
    Write-Host "         kdmapper.exe $DriverPath" -ForegroundColor DarkGray
    Write-Host "  [INFO] Appuie sur Entree quand c'est fait..." -ForegroundColor Yellow
    Read-Host
}
Start-Sleep -Milliseconds 500

# ---------------------------------------------------------------------------
# GROUPE A : Methodes classiques (outils Windows)
# ---------------------------------------------------------------------------
Write-Header "GROUPE A — Methodes classiques"

# A1 - driverquery
$dq = driverquery /v 2>$null
Add-Result "A1 driverquery /v" (-not ($dq | Select-String $SERVICE_NAME -Quiet))

# A2 - sc query
$scq = sc.exe query type= driver state= all 2>$null
Add-Result "A2 sc query (tous drivers)" (-not ($scq | Select-String $SERVICE_NAME -Quiet))

# A3 - WMI Win32_SystemDriver
$wmi = Get-CimInstance Win32_SystemDriver -EA SilentlyContinue |
       Where-Object { $_.Name -like "*$SERVICE_NAME*" -or $_.PathName -like "*$SERVICE_NAME*" }
Add-Result "A3 WMI Win32_SystemDriver" ($null -eq $wmi)

# A4 - Registre Services
Add-Result "A4 Registre HKLM\..\Services" (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$SERVICE_NAME"))

# A5 - EnumDeviceDrivers (WinAPI)
$foundA5 = $false
try {
    $needed = 0u
    [NativeAPI]::EnumDeviceDrivers($null, 0, [ref]$needed) | Out-Null
    $n = $needed / [IntPtr]::Size
    $bases = New-Object IntPtr[] $n
    [NativeAPI]::EnumDeviceDrivers($bases, $needed, [ref]$needed) | Out-Null
    foreach ($b in $bases) {
        $sb = New-Object System.Text.StringBuilder 260
        [NativeAPI]::GetDeviceDriverFileName($b, $sb, 260) | Out-Null
        if ($sb.ToString() -like "*$SERVICE_NAME*") { $foundA5 = $true; break }
    }
} catch {}
Add-Result "A5 EnumDeviceDrivers (PSAPI)" (-not $foundA5)

# ---------------------------------------------------------------------------
# GROUPE B : Methodes anti-cheat (NtQuerySystemInformation)
# ---------------------------------------------------------------------------
Write-Header "GROUPE B — NtQuerySystemInformation (methode anti-cheat)"

# B1 - SystemModuleInformation (classe 11)
# C'est la methode principale d'EAC, BattlEye et Vanguard pour lister
# les modules noyau charges. Elle interroge directement PsLoadedModuleList.
$foundB1 = $false
try {
    $needed = 0u
    [NativeAPI]::NtQuerySystemInformation(11, [IntPtr]::Zero, 0, [ref]$needed) | Out-Null
    $buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([int]$needed + 4096)
    $status = [NativeAPI]::NtQuerySystemInformation(11, $buf, $needed + 4096, [ref]$needed)
    if ($status -eq 0) {
        $count = [System.Runtime.InteropServices.Marshal]::ReadInt32($buf)
        $modSize = [System.Runtime.InteropServices.Marshal]::SizeOf([type][RTL_PROCESS_MODULE_INFORMATION])
        $ptr = [IntPtr]([long]$buf + 4)
        for ($i = 0; $i -lt $count; $i++) {
            $mod = [System.Runtime.InteropServices.Marshal]::PtrToStructure(
                       $ptr, [type][RTL_PROCESS_MODULE_INFORMATION])
            $name = [System.Text.Encoding]::ASCII.GetString($mod.FullPathName).TrimEnd([char]0)
            if ($name -like "*$SERVICE_NAME*") { $foundB1 = $true; break }
            $ptr = [IntPtr]([long]$ptr + $modSize)
        }
    }
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
} catch {}
Add-Result "B1 NtQuerySystemInfo(SystemModuleInformation=11)" (-not $foundB1)

# B2 - SystemHandleInformation (classe 16)
# Cherche un handle ouvert vers le device object du driver.
# BattlEye et Vanguard l'utilisent pour detecter les device objects caches.
$foundB2 = $false
try {
    $needed = 0u
    [NativeAPI]::NtQuerySystemInformation(16, [IntPtr]::Zero, 0, [ref]$needed) | Out-Null
    $buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([int]$needed + 65536)
    $status = [NativeAPI]::NtQuerySystemInformation(16, $buf, $needed + 65536, [ref]$needed)
    # On ne peut pas facilement croiser les handles avec le nom du device sans kernel access
    # => ce test reste indicatif (cherche des handles vers un chemin connu)
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
    # Approximation user-mode : tenter d'ouvrir le device nous-memes
    $testHandle = New-Object System.IO.FileStream("\\.\\$SERVICE_NAME",
                      [System.IO.FileMode]::Open,
                      [System.IO.FileAccess]::Read,
                      [System.IO.FileShare]::ReadWrite) -ErrorAction SilentlyContinue
    if ($testHandle) { $testHandle.Close(); $foundB2 = $true }
} catch {}
Add-Result "B2 Device accessible depuis user-mode (\\.\SelfHideDriver)" (-not $foundB2)

# ---------------------------------------------------------------------------
# GROUPE C : Object Manager (methode Vanguard / PH avance)
# ---------------------------------------------------------------------------
Write-Header "GROUPE C — Object Manager namespace"

# C1 - Enumeration du repertoire \Driver\
# Vanguard et Process Hacker enumerent \Driver\ via NtQueryDirectoryObject
# pour trouver des DRIVER_OBJECT non declares dans PsLoadedModuleList.
$foundC1 = $false
try {
    $objName = "\Driver"
    $ustr = New-Object UNICODE_STRING
    [NativeAPI]::RtlInitUnicodeString([ref]$ustr, $objName) | Out-Null

    $oa = New-Object OBJECT_ATTRIBUTES
    $oa.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($oa)
    $namePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(
                   [System.Runtime.InteropServices.Marshal]::SizeOf($ustr))
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($ustr, $namePtr, $false)
    $oa.ObjectName = $namePtr

    $dirHandle = [IntPtr]::Zero
    $status = [NativeAPI]::NtOpenDirectoryObject([ref]$dirHandle, 0x0001, [ref]$oa)
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($namePtr)

    if ($status -eq 0) {
        $ctx = 0u
        $retLen = 0u
        $bufSize = 4096u
        $buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([int]$bufSize)
        while ($true) {
            $status = [NativeAPI]::NtQueryDirectoryObject($dirHandle, $buf, $bufSize, $false, ($ctx -eq 0), [ref]$ctx, [ref]$retLen)
            if ($status -ne 0) { break }
            $ptr = $buf
            while ($true) {
                $info = [System.Runtime.InteropServices.Marshal]::PtrToStructure(
                            $ptr, [type][OBJECT_DIRECTORY_INFORMATION])
                if ($info.Name.Length -eq 0) { break }
                $entryName = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($info.Name.Buffer, $info.Name.Length / 2)
                if ($entryName -like "*$SERVICE_NAME*") { $foundC1 = $true }
                $ptr = [IntPtr]([long]$ptr + [System.Runtime.InteropServices.Marshal]::SizeOf([type][OBJECT_DIRECTORY_INFORMATION]))
            }
        }
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
        [NativeAPI]::CloseHandle($dirHandle) | Out-Null
    }
} catch {}
Add-Result "C1 Object Manager \Driver\ enumeration" (-not $foundC1)

# ---------------------------------------------------------------------------
# GROUPE D : Notes sur les verifications kernel-only
# ---------------------------------------------------------------------------
Write-Header "GROUPE D — Verifications kernel-mode uniquement (info)"

Write-Host "  Ces methodes necessitent un composant noyau (comme les anti-cheats)." -ForegroundColor DarkGray
Write-Host ""
Write-Host "  D1 PiDDBCacheTable   : table AVL dans ntoskrnl indexee par TimeDateStamp+SizeOfImage" -ForegroundColor DarkGray
Write-Host "     -> verifiable en WinDbg : dt nt!_PiDDBCacheEntry" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  D2 Scan memoire PE   : scan de toutes les pages noyau a la recherche de 'MZ'" -ForegroundColor DarkGray
Write-Host "     -> notre couche 4 (ErasePeHeader) efface cette signature" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  D3 Threads orphelins : thread dont StartAddress pointe hors de tout module connu" -ForegroundColor DarkGray
Write-Host "     -> si le driver cree un PsCreateSystemThread, l'adresse sera suspecte" -ForegroundColor DarkGray

# ---------------------------------------------------------------------------
# DECHARGEMENT
# ---------------------------------------------------------------------------
Write-Header "DECHARGEMENT"
if (-not $KdmapperMode) {
    sc.exe stop $SERVICE_NAME  | Out-Null
    Start-Sleep -Milliseconds 300
    sc.exe delete $SERVICE_NAME | Out-Null
    Write-Host "  Driver stoppe et supprime" -ForegroundColor Gray
} else {
    Write-Host "  [INFO] Mode kdmapper : le driver reste en memoire (pas de DriverUnload standard)" -ForegroundColor Yellow
    Write-Host "         Redemarrer la VM pour nettoyer." -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# RAPPORT
# ---------------------------------------------------------------------------
Write-Header "RAPPORT FINAL"
$total = $PASS + $FAIL
$score = if ($total -gt 0) { [math]::Round(($PASS / $total) * 100) } else { 0 }

$results | Format-Table -AutoSize

$color = if ($score -ge 90) { "Green" } elseif ($score -ge 60) { "Yellow" } else { "Red" }
Write-Host "  Score : " -NoNewline
Write-Host "$score / 100  ($PASS passe, $FAIL echoue, $SKIP skip)" -ForegroundColor $color

if ($FAIL -gt 0) {
    Write-Host "`n  Echecs detectes :" -ForegroundColor Yellow
    $results | Where-Object Resultat -eq "FAIL" | ForEach-Object {
        Write-Host "    -> $($_.Test)" -ForegroundColor DarkYellow
    }
}
