# SelfHideDriver — Driver éducatif (cours cybersécurité)

Driver noyau Windows qui se retire de `PsLoadedModuleList` au chargement,
disparaissant ainsi des outils d'énumération standard.

> **Usage strictement réservé à une VM de laboratoire autorisée.**

---

## Prérequis

- Windows 10/11 **64-bit** en VM
- [WDK](https://learn.microsoft.com/windows-hardware/drivers/download-the-wdk) correspondant à la version Windows
- Visual Studio 2022 avec workload "Desktop development with C++"
- Test signing activé sur la VM :
  ```
  bcdedit /set testsigning on
  # redémarrer la VM
  ```
- [Sysinternals DebugView](https://learn.microsoft.com/sysinternals/downloads/debugview) pour voir les `DbgPrint`

---

## Build

1. Ouvrir `driver/` dans Visual Studio (ou créer un projet WDM vide et y ajouter les sources)
2. Configuration : **Debug / x64**
3. Build → `SelfHideDriver.sys`

### Avec le WDK en ligne de commande (optionnel)
```
msbuild SelfHideDriver.vcxproj /p:Configuration=Debug /p:Platform=x64
```

---

## Chargement (en tant qu'administrateur)

```cmd
sc create SelfHide type= kernel binPath= "C:\chemin\vers\SelfHideDriver.sys"
sc start SelfHide
```

---

## Vérification

Dans DebugView (cocher *Capture Kernel*) :
```
[SelfHide] Driver chargé — dissimulation en cours...
[SelfHide] Retiré de PsLoadedModuleList
```

Puis vérifier l'absence dans :
```cmd
driverquery | findstr SelfHide   # rien ne doit apparaître
```
Et dans Process Explorer → menu View → Show Kernel-mode Drivers.

---

## Déchargement propre

```cmd
sc stop SelfHide
sc delete SelfHide
```

Le driver se ré-insère dans la liste avant de se décharger pour éviter un BSOD.

---

## Concepts illustrés

| Concept | Détail |
|---|---|
| `PsLoadedModuleList` | Liste doublement liée des modules noyau chargés |
| `LDR_DATA_TABLE_ENTRY` | Structure décrivant chaque module (nom, base, taille…) |
| `RemoveEntryList` | Délie une entrée sans libérer la mémoire |
| DKOM | Direct Kernel Object Manipulation — manipulation de structures noyau |
| Restauration au déchargement | Obligatoire pour éviter un accès mémoire invalide (BSOD) |
