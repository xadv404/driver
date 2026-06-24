# SelfHideDriver — CTF / Cours cybersécurité

Driver noyau Windows multi-couches qui se dissimule activement contre des
adversaires disposant d'un accès noyau.

> **Usage réservé à une VM de laboratoire / environnement CTF autorisé.**

---

## Couches de dissimulation implémentées

| # | Technique | Outils trompés |
|---|---|---|
| 1 | Retrait de `PsLoadedModuleList` | `driverquery`, `EnumDeviceDrivers`, Process Hacker, WinDbg `lm` |
| 2 | Effacement des métadonnées LDR (noms, TimeDateStamp, CheckSum) | Scan mémoire brut, `!drvobj`, analyse forensique |
| 3 | Nettoyage de `MmUnloadedDrivers` | Outils de trace d'historique de déchargement |

---

## Techniques avancées (hors implémentation ici)

### PiDDBCacheTable
Le noyau maintient une table AVL (`PiDDBCacheTable`) indexée par
`TimeDateStamp × SizeOfImage` pour chaque driver chargé. Les outils
comme Process Hacker et certains EDR la consultent pour détecter des
drivers cachés.

Pour la nettoyer : il faut chercher `PiDDBCacheTable` dans ntoskrnl par
pattern scan (non exporté, offset variable selon le build), acquérir
`PiDDBLock` (ERESOURCE), puis supprimer l'entrée de la table AVL avec
`RtlDeleteElementGenericTableAvl`. C'est la technique la plus efficace
contre les outils sophistiqués.

### BYOVD (Bring Your Own Vulnerable Driver) comme loader
Concept : charger un driver **signé** mais vulnérable (donc accepté
par DSE), exploiter sa primitive de lecture/écriture noyau pour mapper
manuellement ton propre code en mémoire noyau, puis exécuter ce code
via un thread système (`PsCreateSystemThread`).

Résultat : ton code s'exécute en ring-0 sans jamais passer par le
chargement standard — il n'y a donc **aucune entrée** dans
PsLoadedModuleList, PiDDBCacheTable, ni MmUnloadedDrivers.
Le driver vulnérable peut être déchargé immédiatement après.

---

## Prérequis

- Windows 10/11 VM 64-bit avec test signing :
  ```
  bcdedit /set testsigning on
  # redémarrer
  ```
- WDK + Visual Studio 2022 ("Desktop development with C++")
- Sysinternals DebugView (capture kernel) pour voir les `DbgPrint`

---

## Build & chargement

```cmd
# Compiler avec Visual Studio / MSBuild → SelfHideDriver.sys

sc create SelfHide type= kernel binPath= "C:\...\SelfHideDriver.sys"
sc start SelfHide
```

## Vérification (côté attaquant/espion)

Commandes que le driver doit résister à :

```cmd
driverquery | findstr SelfHide          # doit être vide
```

```powershell
# PowerShell — énumération WMI
Get-WmiObject Win32_SystemDriver | Where-Object Name -like "*SelfHide*"
```

En WinDbg (kernel debug) :
```
lm                    # ne doit pas apparaître
!drvobj SelfHide      # doit échouer
```

## Déchargement propre

```cmd
sc stop SelfHide
sc delete SelfHide
```

La restauration de `PsLoadedModuleList` et le nettoyage de
`MmUnloadedDrivers` se font automatiquement dans `DriverUnload`.
