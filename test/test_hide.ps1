#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Simulation des verifications anti-cheat EAC (Easy Anti-Cheat) contre SelfHideDriver.
    Reproduit les mecanismes de detection kernel et user-mode d'EAC.

.USAGE
    .\test_hide.ps1 -DriverPath "C:\...\SelfHideDriver.sys" [-KdmapperMode]

.NOTES
    Sources : reverse engineering public d'EAC (eac.dll + EasyAntiCheat.sys).
    Checks implementes depuis user-mode via NtQuerySystemInformation et
    Object Manager. Les checks kernel-only (VAD, physique, callbacks) sont
    documentes en section F mais necessitent un driver de test separe.
#>
param(
    [Parameter(Mandatory)]
    [string]$DriverPath,
    [switch]$KdmapperMode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"
$SERVICE_NAME = "SelfHideDriver"
$PASS = 0; $FAIL = 0; $SKIP = 0
$results  = [System.Collections.Generic.List[PSObject]]::new()
$SEVERITY = @{ CRITICAL = "CRITICAL"; HIGH = "HIGH"; MEDIUM = "MEDIUM"; INFO = "INFO" }

# ---------------------------------------------------------------------------
# Types natifs partagés
# ---------------------------------------------------------------------------
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class NT {
    [DllImport("ntdll.dll")]
    public static extern int NtQuerySystemInformation(int cls, IntPtr buf, uint len, out uint needed);

    [DllImport("ntdll.dll")]
    public static extern int NtOpenDirectoryObject(out IntPtr hDir, uint access, ref OBJECT_ATTRIBUTES oa);

    [DllImport("ntdll.dll")]
    public static extern int NtQueryDirectoryObject(IntPtr hDir, IntPtr buf, uint len,
        bool single, bool restart, ref uint ctx, out uint retlen);

    [DllImport("ntdll.dll")]
    public static extern int NtOpenSymbolicLinkObject(out IntPtr hLink, uint access, ref OBJECT_ATTRIBUTES oa);

    [DllImport("ntdll.dll")]
    public static extern int NtQuerySymbolicLinkObject(IntPtr hLink, ref UNICODE_STRING target, out uint retlen);

    [DllImport("ntdll.dll")]
    public static extern void RtlInitUnicodeString(ref UNICODE_STRING dest, [MarshalAs(UnmanagedType.LPWStr)] string src);

    [DllImport("ntdll.dll")]
    public static extern int NtClose(IntPtr h);

    [DllImport("psapi.dll")]
    public static extern bool EnumDeviceDrivers(IntPtr[] bases, uint cb, out uint needed);

    [DllImport("psapi.dll", CharSet=CharSet.Unicode)]
    public static extern uint GetDeviceDriverFileName(IntPtr b, StringBuilder sb, uint n);

    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr h);
}

[StructLayout(LayoutKind.Sequential)]
public struct UNICODE_STRING {
    public ushort Length;
    public ushort MaximumLength;
    public IntPtr Buffer;
}

[StructLayout(LayoutKind.Sequential)]
public struct OBJECT_ATTRIBUTES {
    public uint  Length;
    public IntPtr RootDirectory;
    public IntPtr ObjectName;   // PUNICODE_STRING
    public uint  Attributes;
    public IntPtr SecurityDescriptor;
    public IntPtr SecurityQualityOfService;
}

[StructLayout(LayoutKind.Sequential)]
public struct OBJECT_DIRECTORY_INFORMATION {
    public UNICODE_STRING Name;
    public UNICODE_STRING TypeName;
}

// SystemModuleInformation (class 11)
[StructLayout(LayoutKind.Sequential)]
public struct RTL_PROCESS_MODULE_INFORMATION {
    public IntPtr Section;
    public IntPtr MappedBase;
    public IntPtr ImageBase;
    public uint   ImageSize;
    public uint   Flags;
    public ushort LoadOrderIndex;
    public ushort InitOrderIndex;
    public ushort LoadCount;
    public ushort OffsetToFileName;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst=256)]
    public byte[] FullPathName;
}

// SystemProcessInformation (class 8) - tronque aux champs utiles
[StructLayout(LayoutKind.Sequential)]
public struct SYSTEM_PROCESS_INFORMATION {
    public uint   NextEntryOffset;
    public uint   NumberOfThreads;
    public long   WorkingSetPrivateSize;
    public uint   HardFaultCount;
    public uint   NumberOfThreadsHighWatermark;
    public ulong  CycleTime;
    public long   CreateTime;
    public long   UserTime;
    public long   KernelTime;
    // UNICODE_STRING ImageName (16 bytes sur x64)
    public ushort ImageNameLength;
    public ushort ImageNameMaxLength;
    public IntPtr ImageNameBuffer;
    public int    BasePriority;
    public IntPtr UniqueProcessId;
    public IntPtr InheritedFromUniqueProcessId;
    public uint   HandleCount;
    public uint   SessionId;
    public IntPtr UniqueProcessKey;
    public IntPtr PeakVirtualSize;
    public IntPtr VirtualSize;
    public uint   PageFaultCount;
    // ... + threads qui suivent
}

[StructLayout(LayoutKind.Sequential)]
public struct SYSTEM_THREAD_INFORMATION {
    public long   KernelTime;
    public long   UserTime;
    public long   CreateTime;
    public uint   WaitTime;
    public IntPtr StartAddress;   // adresse de départ du thread — clé EAC
    public IntPtr UniqueProcess;
    public IntPtr UniqueThread;
    public int    Priority;
    public int    BasePriority;
    public uint   ContextSwitches;
    public uint   ThreadState;
    public uint   WaitReason;
}
"@ -ErrorAction Stop

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Section($t) {
    Write-Host "`n╔══════════════════════════════════════════════════╗" -ForegroundColor DarkCyan
    Write-Host "║  $($t.PadRight(48))║" -ForegroundColor DarkCyan
    Write-Host "╚══════════════════════════════════════════════════╝" -ForegroundColor DarkCyan
}

function Add-Result([string]$id, [string]$name, [bool]$hidden, [string]$sev = "HIGH", [bool]$skipped = $false) {
    if ($skipped) {
        Write-Host "  [SKIP]     $id : $name" -ForegroundColor DarkYellow
        $script:SKIP++
        $script:results.Add([PSCustomObject]@{ ID=$id; Test=$name; Resultat="SKIP"; Sev=$sev })
    } elseif ($hidden) {
        Write-Host "  [CACHE]    $id : $name" -ForegroundColor Green
        $script:PASS++
        $script:results.Add([PSCustomObject]@{ ID=$id; Test=$name; Resultat="CACHE"; Sev=$sev })
    } else {
        $col = if ($sev -eq "CRITICAL") { "Red" } else { "Yellow" }
        Write-Host "  [DETECTE]  $id : $name [$sev]" -ForegroundColor $col
        $script:FAIL++
        $script:results.Add([PSCustomObject]@{ ID=$id; Test=$name; Resultat="DETECTE"; Sev=$sev })
    }
}

# Helper : NtQuerySystemInformation avec retry si buffer trop petit
function Invoke-NtQuery([int]$cls) {
    $needed = 0u
    [NT]::NtQuerySystemInformation($cls, [IntPtr]::Zero, 0, [ref]$needed) | Out-Null
    $size = $needed + 65536
    $buf  = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([int]$size)
    $status = [NT]::NtQuerySystemInformation($cls, $buf, $size, [ref]$needed)
    if ($status -ne 0) {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
        return $null
    }
    return $buf   # appelant doit libérer avec FreeHGlobal
}

# Helper : énumération \Object\Directory
function Get-ObjectDirectory([string]$path) {
    $names = @()
    $ustr  = New-Object UNICODE_STRING
    [NT]::RtlInitUnicodeString([ref]$ustr, $path)
    $ustrPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(
                   [System.Runtime.InteropServices.Marshal]::SizeOf($ustr))
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($ustr, $ustrPtr, $false)

    $oa = New-Object OBJECT_ATTRIBUTES
    $oa.Length     = [System.Runtime.InteropServices.Marshal]::SizeOf($oa)
    $oa.ObjectName = $ustrPtr
    $oa.Attributes = 0x40  # OBJ_CASE_INSENSITIVE

    $hDir = [IntPtr]::Zero
    $st   = [NT]::NtOpenDirectoryObject([ref]$hDir, 0x0001, [ref]$oa)
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ustrPtr)
    if ($st -ne 0) { return $names }

    $bufSize = 65536u; $ctx = 0u; $retlen = 0u
    $buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([int]$bufSize)
    $infoSize = [System.Runtime.InteropServices.Marshal]::SizeOf([type][OBJECT_DIRECTORY_INFORMATION])

    while ($true) {
        $st = [NT]::NtQueryDirectoryObject($hDir, $buf, $bufSize, $false, ($ctx -eq 0), [ref]$ctx, [ref]$retlen)
        if ($st -ne 0) { break }
        $ptr = $buf
        while ($true) {
            $info = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ptr, [type][OBJECT_DIRECTORY_INFORMATION])
            if ($info.Name.Length -eq 0) { break }
            $n = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($info.Name.Buffer, $info.Name.Length / 2)
            $names += $n
            $ptr    = [IntPtr]([long]$ptr + $infoSize)
        }
    }
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
    [NT]::NtClose($hDir) | Out-Null
    return $names
}

# ---------------------------------------------------------------------------
# Charger les modules noyau (NtQuerySystemInfo class 11) — réutilisé partout
# ---------------------------------------------------------------------------
function Get-KernelModules {
    $buf = Invoke-NtQuery 11
    if (!$buf) { return @() }
    $modules = @()
    try {
        $count   = [System.Runtime.InteropServices.Marshal]::ReadInt32($buf)
        $msize   = [System.Runtime.InteropServices.Marshal]::SizeOf([type][RTL_PROCESS_MODULE_INFORMATION])
        $ptr     = [IntPtr]([long]$buf + 4)
        for ($i = 0; $i -lt $count; $i++) {
            $m    = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ptr, [type][RTL_PROCESS_MODULE_INFORMATION])
            $name = [System.Text.Encoding]::ASCII.GetString($m.FullPathName).TrimEnd([char]0)
            $modules += [PSCustomObject]@{ Name=$name; Base=$m.ImageBase; Size=$m.ImageSize }
            $ptr  = [IntPtr]([long]$ptr + $msize)
        }
    } finally {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
    }
    return $modules
}

# Cache partagé
$g_KernelModules = $null

# ============================================================
Write-Section "PREREQUIS ET CHARGEMENT"
# ============================================================
if (-not (Test-Path $DriverPath)) {
    Write-Host "[ERREUR] Driver introuvable : $DriverPath" -ForegroundColor Red; exit 1
}
$bcdedit = (bcdedit /enum 2>$null | Select-String "testsigning")
$testSigning = $bcdedit -match "Yes"
Write-Host "  TestSigning   : $(if($testSigning){'ACTIVE'}else{'INACTIF (kdmapper contourne)'})" -ForegroundColor $(if($testSigning){'Green'}else{'Yellow'})
Write-Host "  Mode          : $(if($KdmapperMode){'kdmapper'}else{'sc/NtLoadDriver'})" -ForegroundColor Gray

if (-not $KdmapperMode) {
    sc.exe delete $SERVICE_NAME 2>$null | Out-Null
    sc.exe create $SERVICE_NAME type= kernel binPath= "`"$DriverPath`"" | Out-Null
    $r = sc.exe start $SERVICE_NAME 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERREUR] Chargement echoue : $r" -ForegroundColor Red
        sc.exe delete $SERVICE_NAME 2>$null | Out-Null; exit 1
    }
    Write-Host "  Driver charge via sc.exe" -ForegroundColor Green
} else {
    Write-Host "  [INFO] Charger le driver avec kdmapper AVANT de lancer ce script" -ForegroundColor Yellow
    Write-Host "         Appuie sur Entree quand c'est fait..." -ForegroundColor DarkGray
    Read-Host | Out-Null
}
Start-Sleep -Milliseconds 600

# Cache les modules une fois pour tous les tests
$g_KernelModules = Get-KernelModules

# ============================================================
Write-Section "A — LISTES OFFICIELLES (tier 1, EAC check basique)"
# ============================================================

# A1 — driverquery (appel interne à EnumDeviceDrivers + NtQuerySystemInfo)
$dq = driverquery /v 2>$null
Add-Result "A1" "driverquery /v" (-not ($dq | Select-String $SERVICE_NAME -Quiet)) "MEDIUM"

# A2 — sc query : interroge SCM (Service Control Manager)
$scq = sc.exe query type= driver state= all 2>$null
Add-Result "A2" "sc query type=driver state=all" (-not ($scq | Select-String $SERVICE_NAME -Quiet)) "MEDIUM"

# A3 — WMI Win32_SystemDriver
$wmi = Get-CimInstance Win32_SystemDriver | Where-Object {
    $_.Name -like "*$SERVICE_NAME*" -or $_.PathName -like "*$SERVICE_NAME*" }
Add-Result "A3" "WMI Win32_SystemDriver" ($null -eq $wmi) "MEDIUM"

# A4 — Registre Services (cle persistante)
Add-Result "A4" "Registre HKLM\..\Services" (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$SERVICE_NAME")) "HIGH"

# A5 — EnumDeviceDrivers (PSAPI) : interroge PsLoadedModuleList directement
$foundA5 = $false
$needed5 = 0u
[NT]::EnumDeviceDrivers($null, 0, [ref]$needed5) | Out-Null
$bases5  = New-Object IntPtr[] ($needed5 / [IntPtr]::Size)
[NT]::EnumDeviceDrivers($bases5, $needed5, [ref]$needed5) | Out-Null
foreach ($b in $bases5) {
    $sb = New-Object System.Text.StringBuilder 260
    [NT]::GetDeviceDriverFileName($b, $sb, 260) | Out-Null
    if ($sb.ToString() -like "*$SERVICE_NAME*") { $foundA5 = $true; break }
}
Add-Result "A5" "EnumDeviceDrivers / PSAPI (PsLoadedModuleList)" (-not $foundA5) "HIGH"

# ============================================================
Write-Section "B — NtQuerySystemInformation (verifications EAC primaires)"
# ============================================================

# B1 — SystemModuleInformation (class 11) : methode principale EAC
#      EAC enumere tous les modules noyau charges et cherche des anomalies
$foundB1 = $g_KernelModules | Where-Object { $_.Name -like "*$SERVICE_NAME*" }
Add-Result "B1" "NtQuerySystemInfo(11) SystemModuleInformation" ($null -eq $foundB1 -or @($foundB1).Count -eq 0) "CRITICAL"

# B2 — SystemProcessInformation (class 8) : threads du processus System (PID 4)
#      EAC verifie que chaque thread du processus System a une StartAddress
#      qui appartient a un module connu. Une adresse orpheline = driver cache.
$foundB2 = $false
$knownRanges = $g_KernelModules | ForEach-Object {
    [PSCustomObject]@{ Start=[long]$_.Base; End=[long]$_.Base + [long]$_.Size }
}
$buf8 = Invoke-NtQuery 8
if ($buf8) {
    try {
        $procInfoSize   = [System.Runtime.InteropServices.Marshal]::SizeOf([type][SYSTEM_PROCESS_INFORMATION])
        $threadInfoSize = [System.Runtime.InteropServices.Marshal]::SizeOf([type][SYSTEM_THREAD_INFORMATION])
        $ptr = $buf8
        while ($true) {
            $proc = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ptr, [type][SYSTEM_PROCESS_INFORMATION])
            $pid  = $proc.UniqueProcessId.ToInt64()
            if ($pid -eq 4) {  # System process
                $tptr = [IntPtr]([long]$ptr + $procInfoSize)
                for ($ti = 0; $ti -lt $proc.NumberOfThreads; $ti++) {
                    $t = [System.Runtime.InteropServices.Marshal]::PtrToStructure($tptr, [type][SYSTEM_THREAD_INFORMATION])
                    $addr = $t.StartAddress.ToInt64()
                    # Verifier si l'adresse appartient a un module connu
                    $inModule = $knownRanges | Where-Object { $addr -ge $_.Start -and $addr -lt $_.End }
                    if (-not $inModule -and $addr -gt 0) {
                        Write-Host "    [!] Thread orphelin detecte : StartAddress=0x$($addr.ToString('X16'))" -ForegroundColor Red
                        $foundB2 = $true
                    }
                    $tptr = [IntPtr]([long]$tptr + $threadInfoSize)
                }
            }
            if ($proc.NextEntryOffset -eq 0) { break }
            $ptr = [IntPtr]([long]$ptr + $proc.NextEntryOffset)
        }
    } finally {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf8)
    }
}
Add-Result "B2" "NtQuerySystemInfo(8) — threads System sans module connu" (-not $foundB2) "CRITICAL"

# B3 — SystemModuleInformationEx (class 171, Windows 10 2004+)
#      Version etendue avec infos supplementaires utilisee par certaines versions d'EAC
$foundB3 = $false
$buf171  = Invoke-NtQuery 171
if ($buf171) {
    try {
        # Format similaire a class 11 avec structure etendue
        $count = [System.Runtime.InteropServices.Marshal]::ReadInt32($buf171)
        # On ne peut pas parser proprement sans la structure exacte
        # => Convertir en string ASCII et chercher le nom
        $raw = New-Object byte[] 65536
        [System.Runtime.InteropServices.Marshal]::Copy($buf171, $raw, 0, [Math]::Min(65536, [int]$count * 300 + 8))
        $text = [System.Text.Encoding]::ASCII.GetString($raw)
        if ($text -like "*$SERVICE_NAME*") { $foundB3 = $true }
    } finally {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf171)
    }
    Add-Result "B3" "NtQuerySystemInfo(171) SystemModuleInformationEx" (-not $foundB3) "HIGH"
} else {
    Add-Result "B3" "NtQuerySystemInfo(171) SystemModuleInformationEx" $true "HIGH" -skipped $true
}

# ============================================================
Write-Section "C — OBJECT MANAGER (verifications EAC secondaires)"
# ============================================================

# C1 — Repertoire \Driver\ : EAC enumere tous les DRIVER_OBJECTs
#      Un driver charge officiellement cree un objet dans ce repertoire.
$driverObjs = Get-ObjectDirectory "\Driver"
$foundC1    = $driverObjs | Where-Object { $_ -like "*$SERVICE_NAME*" }
Add-Result "C1" "Object Manager \Driver\ enumeration" ($null -eq $foundC1 -or @($foundC1).Count -eq 0) "HIGH"

# C2 — Repertoire \Device\ : presence d'un device object cree par le driver
$deviceObjs = Get-ObjectDirectory "\Device"
$foundC2    = $deviceObjs | Where-Object { $_ -like "*$SERVICE_NAME*" }
Add-Result "C2" "Object Manager \Device\ enumeration" ($null -eq $foundC2 -or @($foundC2).Count -eq 0) "HIGH"

# C3 — Lien symbolique \DosDevices\ (accessible depuis user-mode via \\.\)
$dosObjs = Get-ObjectDirectory "\DosDevices"
$foundC3 = $dosObjs | Where-Object { $_ -like "*$SERVICE_NAME*" }
Add-Result "C3" "Object Manager \DosDevices\ (lien symbolique)" ($null -eq $foundC3 -or @($foundC3).Count -eq 0) "MEDIUM"

# C4 — Tentative d'ouverture directe du device (CreateFile \\.\NOM)
$foundC4 = $false
try {
    $fs = [System.IO.File]::Open("\\.\$SERVICE_NAME", [System.IO.FileMode]::Open,
                                  [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    if ($fs) { $fs.Dispose(); $foundC4 = $true }
} catch {}
Add-Result "C4" "Acces direct \\.\$SERVICE_NAME (CreateFile)" (-not $foundC4) "MEDIUM"

# ============================================================
Write-Section "D — CROISEMENT DE SOURCES (coherence, methode EAC avancee)"
# ============================================================

# D1 — Coherence NtQuerySystemInfo(11) vs EnumDeviceDrivers
#      EAC compare les deux listes : toute discordance signale une manipulation.
#      Si un module est dans EnumDeviceDrivers mais PAS dans NtQuerySystemInfo(11)
#      ou vice versa, c'est un driver cache (DKOM partiel).
$eBase = [System.Collections.Generic.HashSet[long]]::new()
foreach ($b in $bases5) { if ($b -ne [IntPtr]::Zero) { $eBase.Add($b.ToInt64()) | Out-Null } }

$nBase = [System.Collections.Generic.HashSet[long]]::new()
foreach ($m in $g_KernelModules) { $nBase.Add($m.Base.ToInt64()) | Out-Null }

$onlyInEnum = $eBase | Where-Object { -not $nBase.Contains($_) }
$onlyInNt   = $nBase | Where-Object { -not $eBase.Contains($_) }
$mismatch   = @($onlyInEnum).Count -gt 0 -or @($onlyInNt).Count -gt 0

if ($mismatch) {
    Write-Host "    [!] Discordance detectee :" -ForegroundColor Red
    foreach ($a in $onlyInEnum) { Write-Host "        EnumDeviceDrivers seul : 0x$($a.ToString('X'))" -ForegroundColor DarkRed }
    foreach ($a in $onlyInNt)   { Write-Host "        NtQuerySystemInfo seul  : 0x$($a.ToString('X'))" -ForegroundColor DarkRed }
}
Add-Result "D1" "Coherence EnumDeviceDrivers <-> NtQuerySystemInfo(11)" (-not $mismatch) "CRITICAL"

# D2 — Plages memoire noyau non rattachees a un module
#      EAC verifie que chaque plage memoire noyau executable correspond
#      a un module liste. Approximation user-mode : base addresses insolites.
$knownBases = $g_KernelModules | ForEach-Object { $_.Base.ToInt64() }
$anonDrivers = foreach ($b in $bases5) {
    $ba = $b.ToInt64()
    if ($ba -ne 0 -and $ba -notin $knownBases) {
        $sb = New-Object System.Text.StringBuilder 260
        [NT]::GetDeviceDriverFileName($b, $sb, 260) | Out-Null
        if ($sb.ToString() -eq "") { $ba }  # base sans nom = region anonyme
    }
}
Add-Result "D2" "Regions memoire noyau anonymes (non rattachees a un module)" (@($anonDrivers).Count -eq 0) "HIGH"

# D3 — Verification de la consistance NtQuerySystemInfo(11) vs \Driver\
#      Chaque entree dans \Driver\ devrait correspondre a un module charge.
$driverObjNames = $driverObjs
$moduleNames = $g_KernelModules | ForEach-Object {
    [System.IO.Path]::GetFileNameWithoutExtension($_.Name).ToLower() }
$orphanDriverObjs = $driverObjNames | Where-Object {
    $n = $_.ToLower()
    # Exclure les drivers Windows connus qui n'ont pas de module LDR
    $n -notin @("null","beep","cdrom","disk","volume","volsnap","partmgr") -and
    $n -notin $moduleNames
}
if (@($orphanDriverObjs).Count -gt 0) {
    Write-Host "    [!] Driver objects sans module LDR correspondant :" -ForegroundColor Yellow
    $orphanDriverObjs | ForEach-Object { Write-Host "        \Driver\$_" -ForegroundColor DarkYellow }
}
# Ce test est indicatif : beaucoup de drivers legit n'ont pas de nom LDR matching
# On cherche uniquement notre cible
$ourInDriverDir = $driverObjNames | Where-Object { $_ -like "*$SERVICE_NAME*" }
Add-Result "D3" "Coherence \Driver\ <-> NtQuerySystemInfo(11)" ($null -eq $ourInDriverDir -or @($ourInDriverDir).Count -eq 0) "HIGH"

# ============================================================
Write-Section "E — HANDLES ET ACCES PROCESSUS (EAC user-mode)"
# ============================================================

# E1 — SystemHandleInformation (class 16) : handles vers notre device/driver
$foundE1 = $false
$buf16 = Invoke-NtQuery 16
if ($buf16) {
    try {
        $raw = New-Object byte[] 131072
        [System.Runtime.InteropServices.Marshal]::Copy($buf16, $raw, 0, [Math]::Min(131072, $raw.Length))
        $text = [System.Text.Encoding]::Unicode.GetString($raw)
        if ($text -like "*$SERVICE_NAME*") { $foundE1 = $true }
    } finally {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf16)
    }
}
Add-Result "E1" "NtQuerySystemInfo(16) SystemHandleInformation" (-not $foundE1) "MEDIUM"

# E2 — Verificiation du code integrite (CodeIntegrityInformation = class 103)
#      EAC verifie que HVCI / CI est actif et que le driver a passe la validation
$buf103 = Invoke-NtQuery 103
if ($buf103) {
    $ciFlags = [System.Runtime.InteropServices.Marshal]::ReadInt32($buf103)
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf103)
    $hvciActive = ($ciFlags -band 0x2) -ne 0
    Write-Host "    [i] Code Integrity flags : 0x$($ciFlags.ToString('X'))" -ForegroundColor DarkGray
    Write-Host "    [i] HVCI actif           : $hvciActive" -ForegroundColor DarkGray
    if ($hvciActive) {
        Write-Host "    [!] HVCI actif : ni sc ni kdmapper ne peuvent charger un driver non signe !" -ForegroundColor Red
    }
    Add-Result "E2" "HVCI desactive (condition pour charger le driver)" (-not $hvciActive) "CRITICAL"
} else {
    Add-Result "E2" "HVCI desactive" $true "CRITICAL" -skipped $true
}

# ============================================================
Write-Section "F — KERNEL-ONLY : NON TESTABLES ICI (informatif)"
# ============================================================
Write-Host "  Ces verifications necessitent un driver de test avec acces noyau." -ForegroundColor DarkGray
Write-Host "  EAC les effectue via EasyAntiCheat.sys." -ForegroundColor DarkGray
Write-Host ""
Write-Host "  F1 [CRITICAL] Scan memoire physique (MmPhysicalMemoryBlock)" -ForegroundColor DarkGray
Write-Host "     Scan toutes les pages physiques a la recherche de signatures PE" -ForegroundColor DarkGray
Write-Host "     Notre couche 4 (ErasePeHeaderPhys) neutralise partiellement ceci" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  F2 [CRITICAL] VAD (Virtual Address Descriptors)" -ForegroundColor DarkGray
Write-Host "     EAC parcourt l'arbre VAD du processus System pour trouver" -ForegroundColor DarkGray
Write-Host "     des allocations non rattachees a un module" -ForegroundColor DarkGray
Write-Host "     NOTRE DRIVER EST DETECTABLE ICI — point faible majeur" -ForegroundColor Red
Write-Host ""
Write-Host "  F3 [HIGH]     Callbacks noyau (PsSetCreateProcessNotifyRoutine, etc.)" -ForegroundColor DarkGray
Write-Host "     Verifie que chaque callback pointe dans un module connu" -ForegroundColor DarkGray
Write-Host "     Notre driver n'enregistre pas de callbacks — F3 passe" -ForegroundColor Green
Write-Host ""
Write-Host "  F4 [HIGH]     PiDDBCacheTable (TimeDateStamp lookup)" -ForegroundColor DarkGray
Write-Host "     Notre couche 1c nettoie cette table — F4 devrait passer" -ForegroundColor Green

# ============================================================
Write-Section "DECHARGEMENT"
# ============================================================
if (-not $KdmapperMode) {
    sc.exe stop $SERVICE_NAME | Out-Null
    Start-Sleep -Milliseconds 300
    sc.exe delete $SERVICE_NAME | Out-Null
    Write-Host "  Driver stoppe et supprime." -ForegroundColor Gray
} else {
    Write-Host "  Mode kdmapper : redemarrer la VM pour nettoyer." -ForegroundColor Yellow
}

# ============================================================
Write-Section "RAPPORT FINAL EAC"
# ============================================================
$total     = $PASS + $FAIL
$score     = if ($total -gt 0) { [math]::Round(($PASS / $total) * 100) } else { 0 }
$critical  = @($results | Where-Object { $_.Resultat -eq "DETECTE" -and $_.Sev -eq "CRITICAL" }).Count
$high      = @($results | Where-Object { $_.Resultat -eq "DETECTE" -and $_.Sev -eq "HIGH"     }).Count

$results | Format-Table ID, Test, Resultat, Sev -AutoSize

$color = if ($score -ge 90) { "Green" } elseif ($score -ge 70) { "Yellow" } else { "Red" }
Write-Host ""
Write-Host "  Score de discrecion : " -NoNewline
Write-Host "$score / 100" -ForegroundColor $color -NoNewline
Write-Host "  ($PASS caches, $FAIL detectes dont $critical CRITICAL / $high HIGH)"

Write-Host ""
Write-Host "  Note : F2 (VAD) est le vecteur de detection residuel le plus serieux." -ForegroundColor DarkYellow
Write-Host "  Pour le neutraliser : manipuler l'arbre VAD du processus System" -ForegroundColor DarkYellow
Write-Host "  (EPROCESS.VadRoot) pour masquer la region allouee par le driver." -ForegroundColor DarkYellow
