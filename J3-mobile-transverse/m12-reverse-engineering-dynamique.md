# Module 12 — Reverse Engineering & Analyse Dynamique

> **Niveau :** M2 — Red Team / Sécurité Offensive
> **Durée :** 1h15
> **Prérequis :** Module 11 (fondamentaux pentest mobile), connaissances Frida de base, Java/Kotlin
> **Objectif :** Maîtriser le reverse engineering Android avancé, l'instrumentation dynamique avec Frida, l'analyse du stockage local et l'interception réseau avancée
> **Tags MITRE ATT&CK :** T1407, T1406, T1040, T1412, T1402, T1456

---

## Table des matières

1. [Reverse engineering Android avancé (T1407)](#1-reverse-engineering-android-avancé-t1407)
2. [Frida — Instrumentation dynamique (T1406)](#2-frida--instrumentation-dynamique-t1406)
3. [Analyse de stockage local (T1407)](#3-analyse-de-stockage-local-t1407)
4. [Analyse réseau avancée (T1040)](#4-analyse-réseau-avancée-t1040)
5. [TP Guidé — Analyse dynamique complète](#5-tp-guidé--analyse-dynamique-complète)
6. [Références](#6-références)

---

## 1. Reverse engineering Android avancé (T1407)

### 1.1 Smali — L'assembleur Dalvik

Smali est au bytecode Dalvik ce que l'assembleur est au code machine. Quand on décompile une APK avec apktool, le code compilé (classes.dex) est converti en fichiers `.smali` — une représentation textuelle lisible (et modifiable) du bytecode Dalvik.

```
┌──────────────────────────────────────────────────────────────┐
│       CHAÎNE DE COMPILATION / DÉCOMPILATION DALVIK           │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│   ┌──────────────┐    javac     ┌──────────────┐             │
│   │ Code source  │ ───────────► │  Bytecode    │             │
│   │   (.java)    │              │   (.class)    │             │
│   └──────────────┘              └──────┬───────┘             │
│                                        │                      │
│                                 dx/d8  │                      │
│                                        ▼                      │
│                                 ┌──────────────┐             │
│                                 │  Dalvik      │             │
│                                 │ Executable    │             │
│                                 │  (.dex)       │             │
│                                 └──────┬───────┘             │
│                                        │                      │
│                       ┌────────────────┼────────────────┐     │
│                       │                │                │     │
│                  apktool d       baksmali           dex2jar │
│                       │                │                │     │
│                       ▼                ▼                ▼     │
│                ┌────────────┐  ┌────────────┐  ┌──────────┐  │
│                │  .smali    │  │  .smali    │  │  .jar    │  │
│                │ (apktool)  │  │ (baksmali) │  │ (JD-GUI) │  │
│                └────────────┘  └────────────┘  └──────────┘  │
│                                                               │
│   SENS INVERSE (MODIFICATION) :                               │
│   .smali ──apktool b──► APK modifiée ──sign──► APK signée    │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

#### 1.1.1 Syntaxe et conventions Smali

Smali utilise une syntaxe très proche des mnémoniques assembleur. Chaque fichier `.smali` correspond à une classe Java et contient les définitions des champs et méthodes.

**Structure d'un fichier smali :**

```smali
.class public Lcom/example/vulnapp/LoginActivity;
.super Landroid/support/v7/app/AppCompatActivity;
.source "LoginActivity.java"

# ============================================================
# CHAMPS (FIELDS)
# ============================================================

# Champ d'instance privé — String
.field private apiKey:Ljava/lang/String;

# Champ statique public — int
.field public static MAX_ATTEMPTS:I = 0x3

# Champ avec annotation
.field private password:Ljava/lang/String;
    .annotation build Landroid/support/annotation/Nullable;
    .end annotation
.end field

# ============================================================
# MÉTHODES (METHODS)
# ============================================================

# Constructeur
.method public constructor <init>()V
    .locals 1

    .param p0, "this"   # p0 = this (référence à l'instance)

    # Invocation du constructeur parent
    invoke-direct {p0}, Landroid/support/v7/app/AppCompatActivity;-><init>()V

    return-void
.end method

# Méthode onCreate
.method protected onCreate(Landroid/os/Bundle;)V
    .locals 2

    .param p1, "savedInstanceState"

    invoke-super {p0, p1}, Landroid/support/v7/app/AppCompatActivity;->onCreate(Landroid/os/Bundle;)V

    # Charger une constante dans un registre
    const-string v0, "AIzaSyDummyKey1234567890"

    # Stocker dans le champ apiKey
    iput-object v0, p0, Lcom/example/vulnapp/LoginActivity;->apiKey:Ljava/lang/String;

    const v0, 0x7f0b001c
    invoke-virtual {p0, v0}, Lcom/example/vulnapp/LoginActivity;->setContentView(I)V

    return-void
.end method

# Méthode de vérification de login (intéressante à patcher !)
.method private checkPassword(Ljava/lang/String;)Z
    .locals 3

    .param p1, "input"

    iget-object v0, p0, Lcom/example/vulnapp/LoginActivity;->password:Ljava/lang/String;

    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    return v1
.end method
```

**Correspondance Smali ↔ Java :**

| Java | Smali | Description |
|------|-------|-------------|
| `int x = 5;` | `const/4 v0, 0x5` | Constante 32-bit |
| `String s = "test";` | `const-string v0, "test"` | Chaîne constante |
| `void` | `V` | Type de retour void |
| `boolean` | `Z` | Boolean |
| `int` | `I` | Integer |
| `long` | `J` | Long |
| `float` | `F` | Float |
| `double` | `D` | Double |
| `String` | `Ljava/lang/String;` | Classe Java |
| `int[]` | `[I` | Tableau d'int |
| `String[]` | `[Ljava/lang/String;` | Tableau de String |
| `obj.method()` | `invoke-virtual {p0}, ...->method()V` | Appel virtuel |
| `Class.method()` | `invoke-static {}, ...->method()V` | Appel statique |
| `return x;` | `return v0` | Retourner valeur |
| `return;` | `return-void` | Retourner void |
| `if (x == 0)` | `if-eqz v0, :cond_0` | Branchement conditionnel |
| `x.field = y;` | `iput-object v1, p0, ...->field` | Assigner champ instance |
| `y = x.field;` | `iget-object v0, p0, ...->field` | Lire champ instance |

**Mnémoniques smali essentiels :**

```smali
# INVOCATION DE MÉTHODES
invoke-virtual   {params}, Classe->methode(params)Retour  # Méthode d'instance
invoke-static    {params}, Classe->methode(params)Retour  # Méthode statique
invoke-direct    {params}, Classe->methode(params)Retour  # Constructeur / private
invoke-super     {params}, Classe->methode(params)Retour  # Méthode parente
invoke-interface {params}, Classe->methode(params)Retour  # Interface

# MANIPULATION DE REGISTRES
move vA, vB           # vA = vB
move-result vA        # Récupère le résultat d'un invoke précédent
move-result-object vA # Idem pour les objets
move-exception vA     # Récupère l'exception (dans catch)

# CONSTANTES
const/4 vA, #int      # Constante 4 bits (-8 à 7)
const/16 vA, #int     # Constante 16 bits
const vA, #int        # Constante 32 bits
const/high16 vA, #int # Constante 32 bits (16 bits hauts)
const-string vA, "str"# Chaîne de caractères (table strings)

# ARITHMÉTIQUE
add-int vA, vB, vC    # vA = vB + vC
sub-int vA, vB, vC    # vA = vB - vC
mul-int vA, vB, vC    # vA = vB * vC
div-int vA, vB, vC    # vA = vB / vC

# BRANCHEMENTS
if-eqz vA, :label     # Si vA == 0, aller à :label
if-nez vA, :label     # Si vA != 0, aller à :label
if-eq vA, vB, :label  # Si vA == vB
if-ne vA, vB, :label  # Si vA != vB
goto :label           # Saut inconditionnel

# ACCÈS AUX CHAMPS
iget vA, p0, Classe;->champ:Type         # Lire champ instance (int)
iget-object vA, p0, Classe;->champ:LType; # Lire champ instance (objet)
iput vA, p0, Classe;->champ:Type         # Écrire champ instance (int)
sget vA, Classe;->champ:Type             # Lire champ statique
sput vA, Classe;->champ:Type             # Écrire champ statique
```

### 1.2 Modification de code Smali (patching)

La modification de code smali permet de changer le comportement d'une application sans avoir accès au code source. C'est une technique de reverse engineering très puissante.

```
┌──────────────────────────────────────────────────────────────┐
│              WORKFLOW DE PATCHING SMALI                       │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│   ┌─────────┐    apktool d     ┌──────────────┐              │
│   │ APK     │ ───────────────► │ .smali       │              │
│   │ Original│                  │ modifiables   │              │
│   └─────────┘                  └──────┬───────┘              │
│                                       │                       │
│                         ┌─────────────┼─────────────┐        │
│                         │             │             │         │
│                   Édition smali   Édition XML   Édition      │
│                   (code)          (manifest)    ressources    │
│                         │             │             │         │
│                         └─────────────┼─────────────┘        │
│                                       │                       │
│                                apktool b                      │
│                                       │                       │
│                                       ▼                       │
│                                 ┌──────────────┐              │
│                                 │ APK non      │              │
│                                 │ signée       │              │
│                                 └──────┬───────┘              │
│                                        │                      │
│                              Signer avec jarsigner/apksigner  │
│                                        │                      │
│                                        ▼                      │
│                                 ┌──────────────┐              │
│                                 │ APK signée   │              │
│                                 │ → installable │              │
│                                 └──────────────┘              │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

#### 1.2.1 Patch 1 : Contournement de Root Detection (T1406)

Beaucoup d'applications (notamment bancaires) détectent si le device est rooté et refusent de s'exécuter. Nous allons patcher ce comportement.

**Code Java original (exemple) :**

```java
public class RootDetection {
    private static final String[] ROOT_PATHS = {
        "/system/app/Superuser.apk",
        "/sbin/su",
        "/system/bin/su",
        "/system/xbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/local/su",
        "/su/bin/su"
    };

    public static boolean isDeviceRooted() {
        for (String path : ROOT_PATHS) {
            if (new File(path).exists()) {
                return true;
            }
        }
        return false;
    }
}
```

**Code smali correspondant (avant patch) :**

```smali
.method public static isDeviceRooted()Z
    .locals 5

    sget-object v0, Lcom/example/vulnapp/RootDetection;->ROOT_PATHS:[Ljava/lang/String;
    array-length v1, v0

    const/4 v2, 0x0

    :loop_start
    if-ge v2, v1, :cond_end_loop

    aget-object v3, v0, v2

    new-instance v4, Ljava/io/File;
    invoke-direct {v4, v3}, Ljava/io/File;-><init>(Ljava/lang/String;)V
    invoke-virtual {v4}, Ljava/io/File;->exists()Z
    move-result v4

    if-eqz v4, :cond_not_found
    const/4 v0, 0x1
    return v0

    :cond_not_found
    add-int/lit8 v2, v2, 0x1
    goto :loop_start

    :cond_end_loop
    const/4 v0, 0x0
    return v0
.end method
```

**Patch smali — Forcer le retour à `false` (0x0) :**

```smali
.method public static isDeviceRooted()Z
    .locals 1

    # PATCH : Retourne toujours 0 (false)
    const/4 v0, 0x0
    return v0
.end method
```

**Autre approche — patcher le `if` :**

```smali
# Au lieu de supprimer tout le code, on peut juste inverser la condition :
# Remplacer if-eqz (si == 0) par if-nez (si != 0)
# ou simplement remplacer const/4 v0, 0x1 par const/4 v0, 0x0
```

#### 1.2.2 Patch 2 : Bypass de login (T1402)

Objectif : modifier la logique d'authentification pour qu'elle réussisse toujours, quel que soit le mot de passe saisi.

**Code Java original :**

```java
public class LoginActivity {
    private boolean validateCredentials(String username, String password) {
        return apiClient.authenticate(username, password);
    }

    public void onLoginClick(View view) {
        String username = usernameEditText.getText().toString();
        String password = passwordEditText.getText().toString();

        if (validateCredentials(username, password)) {
            startActivity(new Intent(this, HomeActivity.class));
        } else {
            showError("Invalid credentials");
        }
    }
}
```

**Code smali de `validateCredentials` :**

```smali
.method private validateCredentials(Ljava/lang/String;Ljava/lang/String;)Z
    .locals 3

    .param p1, "username"
    .param p2, "password"

    iget-object v0, p0, Lcom/example/vulnapp/LoginActivity;->apiClient:Lcom/example/ApiClient;

    invoke-virtual {v0, p1, p2}, Lcom/example/ApiClient;->authenticate(Ljava/lang/String;Ljava/lang/String;)Z

    move-result v0
    return v0
.end method
```

**Patch smali — `validateCredentials` retourne toujours `true` :**

```smali
.method private validateCredentials(Ljava/lang/String;Ljava/lang/String;)Z
    .locals 1

    .param p1, "username"
    .param p2, "password"

    # PATCH : retourne toujours true (1)
    const/4 v0, 0x1
    return v0
.end method
```

**Alternative — Patcher directement dans `onLoginClick` :**

```smali
# Plutôt que de patcher la méthode validateCredentials,
# on peut inverser la condition dans onLoginClick

# Code original :
#   if-eqz v0, :label_error    # Si v0 == 0 (false) → erreur
# Patch :
#   if-nez v0, :label_error    # Si v0 != 0 → erreur (inversé)
#   → OU supprimer le branchement complètement
```

#### 1.2.3 Patch 3 : Contournement de détection d'émulateur (T1406)

```smali
# Code original : vérifie si on est sur un émulateur
.method public static isEmulator()Z
    .locals 2

    sget-object v0, Landroid/os/Build;->FINGERPRINT:Ljava/lang/String;

    const-string v1, "generic"
    invoke-virtual {v0, v1}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z
    move-result v0

    return v0
.end method

# PATCH — force le retour à false
.method public static isEmulator()Z
    .locals 1

    const/4 v0, 0x0
    return v0
.end method
```

### 1.3 Recompilation de l'APK modifiée

```bash
cd ~/pentest-mobile/patching

# Étape 1 : Décompiler
apktool d cible.apk -o cible_patched -f

# Étape 2 : Modifier les fichiers .smali
# Éditer les fichiers smali avec un éditeur de texte
# Exemple : vim cible_patched/smali/com/example/MainActivity.smali
# Appliquer les patches décrits ci-dessus

# Étape 3 : Recompiler
apktool b cible_patched -o cible_patched.apk
# Output attendu :
# I: Using Apktool 2.9.3
# I: Copying assets and libs...
# I: Building apk file...

# Étape 4 : Générer une clé de signature (si première fois)
keytool -genkey -v \
    -keystore ~/pentest-mobile/my-release-key.keystore \
    -alias pentest_alias \
    -keyalg RSA \
    -keysize 2048 \
    -validity 10000 \
    -storepass password123 \
    -keypass password123 \
    -dname "CN=Red Team, OU=Pentest, O=Training, L=Paris, ST=IDF, C=FR"

# Étape 5 : Signer l'APK — Méthode 1 (jarsigner, ancienne)
jarsigner -verbose \
    -sigalg SHA1withRSA \
    -digestalg SHA1 \
    -keystore ~/pentest-mobile/my-release-key.keystore \
    -storepass password123 \
    -keypass password123 \
    cible_patched.apk \
    pentest_alias

# Étape 5 bis : Signer l'APK — Méthode 2 (apksigner, recommandée)
# Détection automatique du dossier build-tools
BUILD_TOOLS=$(ls -d ~/Android/Sdk/build-tools/*/ 2>/dev/null | sort -V | tail -1)
if [ -z "$BUILD_TOOLS" ]; then
    echo "[-] Android SDK build-tools introuvable. Installer via Android Studio > SDK Manager."
    exit 1
fi
$BUILD_TOOLS/zipalign -v 4 cible_patched.apk cible_aligned.apk

# Signature avec apksigner (Android 7+, v2/v3)
$BUILD_TOOLS/apksigner sign \
    --ks ~/pentest-mobile/my-release-key.keystore \
    --ks-pass pass:password123 \
    --key-pass pass:password123 \
    --ks-key-alias pentest_alias \
    cible_aligned.apk

# Vérifier la signature
$BUILD_TOOLS/apksigner verify cible_aligned.apk

# Étape 6 : Installer l'APK patchée
adb uninstall com.example.vulnapp
adb install cible_aligned.apk
```

**Problèmes courants et solutions :**

| Problème | Solution |
|----------|----------|
| `INSTALL_FAILED_UPDATE_INCOMPATIBLE` | Signature différente → `adb uninstall` d'abord |
| `INSTALL_PARSE_FAILED_NO_CERTIFICATES` | APK non signée → signer avec jarsigner/apksigner |
| `INSTALL_FAILED_INVALID_APK` | APK corrompue → revérifier le patching |
| L'app crash au lancement | Erreur dans le smali modifié → vérifier la syntaxe |
| `INSTALL_FAILED_DUPLICATE_PERMISSION` | Permissions custom en conflit → comparer les manifest |

### Exercice concret — Patch de DIVA
1. Décompiler l'APK : `apktool d DivaApplication.apk -o diva_patched`
2. Ouvrir `diva_patched/smali/jakhar/aseem/diva/InsecureLoginActivity.smali`
3. Chercher la méthode `onCreate` et modifier la vérification...

### 1.4 Objection — Framework d'analyse runtime (T1406)

Objection est un framework basé sur Frida qui simplifie les tâches courantes de pentest mobile. Il fournit une CLI interactive avec des commandes prêtes à l'emploi.

```bash
# Installation (côté hôte)
pip install objection

# Vérifier
objection --version
```

```
┌──────────────────────────────────────────────────────────────┐
│              OBJECTION — COMMANDES CLÉS                       │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  CATÉGORIE          COMMANDE              DESCRIPTION        │
│  ──────────────     ───────────────────   ─────────────────  │
│                                                               │
│  Device Info        env                   Info environnement  │
│                     android shelf         Lire le filesystem   │
│                                                               │
│  Hooking            android hooking list  Lister les hooks    │
│                     android hooking       Voir classes/méthodes│
│                       list classes                            │
│                     android hooking       Hooker une méthode   │
│                       watch class                              │
│                                                               │
│  SSL Pinning        android sslpinning    Bypass SSL Pinning  │
│                       disable             automatique          │
│                                                               │
│  Root Detection     android root disable  Bypass Root Detect   │
│                     android root simulate Simuler non-root     │
│                                                               │
│  Keystore           android keystore list Lister les entrées   │
│                     android keystore     Dump les clés        │
│                       watch                                   │
│                                                               │
│  Heap               android heap search   Chercher en mémoire  │
│                     android heap execute  Exécuter du code    │
│                       js                                     │
│                                                               │
│  SQLite             android sqlite list   Lister les BDD      │
│                     android sqlite        Dump une BDD        │
│                       connect                                  │
│                                                               │
│  File System        android shell ls      Lister répertoire    │
│                     android download      Télécharger fichier  │
│                     android upload        Uploader fichier     │
│                                                               │
│  Intents            android intent launch Lancer une activité  │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

**Utilisation basique d'Objection :**

```bash
# Lancer Objection sur une application
objection -g com.example.vulnapp explore
# -g : package name de l'application cible
# explore : mode interactif

# Le prompt Objection apparaît :
# [com.example.vulnapp on Android (emulator-5554)] →

# Informations sur l'environnement
env
# Affiche : version Android, SDK, device, paths, etc.

# Lister les classes chargées
android hooking list classes

# Filtrer les classes par pattern
android hooking list classes | grep -i "login\|auth\|crypto"

# Lister les méthodes d'une classe spécifique
android hooking list class_methods com.example.vulnapp.LoginActivity

# Watcher une classe (hooker toutes les méthodes)
android hooking watch class com.example.vulnapp.LoginActivity
# → Toutes les invocations de méthodes seront loggées en direct

# Watcher une méthode spécifique avec arguments et retour
android hooking watch class_method com.example.vulnapp.LoginActivity.validateCredentials \
    --dump-args --dump-return --dump-backtrace

# Bypass SSL Pinning automatique
android sslpinning disable

# Bypass Root Detection
android root disable

# Lister les bases de données SQLite
android sqlite list

# Se connecter à une BDD et exécuter des requêtes
android sqlite connect /data/data/com.example.vulnapp/databases/app.db
sqlite> .tables
sqlite> SELECT * FROM users;
sqlite> .quit
```

---

## 2. Frida — Instrumentation dynamique (T1406)

### 2.1 Architecture détaillée de Frida

```
┌──────────────────────────────────────────────────────────────┐
│         ARCHITECTURE FRIDA — DÉTAIL INTERNE                   │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─────────────────────────────────────────────────────┐     │
│  │                    HÔTE (PC)                         │     │
│  │                                                     │     │
│  │  ┌──────────────┐    USB/TCP:27042    ┌──────────┐ │     │
│  │  │ frida CLI    │ ◄─────────────────► │ frida-   │ │     │
│  │  │ frida-ps     │                     │ server   │ │     │
│  │  │ frida-trace  │                     │ (root)   │ │     │
│  │  │ frida-discover│                    └────┬─────┘ │     │
│  │  │ frida-kill   │                         │       │     │
│  │  └──────────────┘                         │       │     │
│  │                                           ▼       │     │
│  │  ┌──────────────────────────────────────────────┐ │     │
│  │  │  Scripts Frida (JavaScript)                  │ │     │
│  │  │  → Java.perform(), Interceptor.attach()      │ │     │
│  │  │  → Module.findExportByName()                 │ │     │
│  │  │  → NativeFunction(), NativeCallback()        │ │     │
│  │  └──────────────────────────────────────────────┘ │     │
│  └─────────────────────────────────────────────────────┘     │
│                                                               │
│  ┌─────────────────────────────────────────────────────┐     │
│  │                  DEVICE ANDROID                      │     │
│  │                                                     │     │
│  │  ┌──────────────────────────────────────────────┐   │     │
│  │  │          PROCESSUS CIBLE (App)                │   │     │
│  │  │                                              │   │     │
│  │  │  ┌──────────────────────────────────────┐    │   │     │
│  │  │  │         FRIDA AGENT (.so)             │    │   │     │
│  │  │  │                                       │    │   │     │
│  │  │  │  → Injecté dans le processus          │    │   │     │
│  │  │  │  → Moteur JavaScript Duktape/QuickJS   │    │   │     │
│  │  │  │  → Pont JS ↔ Java (Dalvik/ART)        │    │   │     │
│  │  │  │  → Pont JS ↔ Native (libc)            │    │   │     │
│  │  │  └──────────────────────────────────────┘    │   │     │
│  │  └──────────────────────────────────────────────┘   │     │
│  └─────────────────────────────────────────────────────┘     │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

### 2.2 Scripts Frida — Fondamentaux

#### 2.2.1 Structure de base d'un script Frida

```bash
# Sauvegarder ce script (ex: mon_script.js) puis exécuter :
cat > mon_script.js << 'JSEOF'
```

```javascript
// mon_script.js — Template de script Frida T1406

Java.perform(function() {
    console.log("[*] Script Frida chargé dans le processus");

    // 1. Récupérer une référence vers une classe
    var MyClass = Java.use("com.example.vulnapp.MainActivity");

    // 2. Hooker une méthode (remplacer l'implémentation)
    MyClass.vulnerableMethod.implementation = function(arg1, arg2) {
        console.log("[+] vulnerableMethod appelée avec: " + arg1 + ", " + arg2);

        // Appeler l'implémentation originale
        var result = this.vulnerableMethod(arg1, arg2);
        console.log("[+] vulnerableMethod a retourné: " + result);

        // Possibilité de modifier le retour
        return result;
    };

    console.log("[*] Hooks installés avec succès");
});
```

JSEOF
frida -U -l mon_script.js -f com.example.vulnapp --no-pause
```

#### 2.2.2 Hook de fonctions Java et dump de variables (T1406)

```bash
# Sauvegarder ce script (ex: hook_and_dump.js) puis exécuter :
cat > hook_and_dump.js << 'JSEOF'
```

```javascript
// hook_and_dump.js — Hooker et dumper des variables

Java.perform(function() {

    // Hook 1 : Récupérer les arguments d'une méthode d'authentification
    var LoginActivity = Java.use("com.example.vulnapp.LoginActivity");

    LoginActivity.validateCredentials.implementation = function(username, password) {
        console.log("[=== CREDENTIALS CAPTURÉES ===]");
        console.log("[*] Username: " + username);
        console.log("[*] Password: " + password);
        console.log("[==============================]");

        // Appeler l'original
        return this.validateCredentials(username, password);
    };

    // Hook 2 : Dump des SharedPreferences
    var SharedPreferences = Java.use("android.content.SharedPreferences");
    var Editor = Java.use("android.content.SharedPreferences$Editor");

    SharedPreferences.getString.overload("java.lang.String", "java.lang.String").implementation = function(key, defValue) {
        var value = this.getString(key, defValue);
        console.log("[SP GET] Key: " + key + " = " + value);
        return value;
    };

    // Hook 3 : Dump des variables d'instance d'une classe
    var TargetClass = Java.use("com.example.vulnapp.SecretStorage");
    Java.choose("com.example.vulnapp.SecretStorage", {
        onMatch: function(instance) {
            console.log("[+] Instance trouvée: " + instance);
            console.log("    apiKey: " + instance.apiKey.value);
            console.log("    secretToken: " + instance.secretToken.value);
        },
        onComplete: function() {
            console.log("[*] Scan terminé");
        }
    });

    // Hook 4 : Intercepter les Intents
    var Intent = Java.use("android.content.Intent");
    Intent.getStringExtra.implementation = function(name) {
        var value = this.getStringExtra(name);
        console.log("[INTENT] getStringExtra: " + name + " = " + value);
        return value;
    };
});
```

JSEOF
frida -U -l hook_and_dump.js -f com.example.vulnapp
```

### 2.3 Bypass SSL Pinning — Script universal (T1406)

```javascript
// universal_ssl_pinning_bypass.js — Bypass SSL Pinning Android
// T1406 — Contournement de Certificate Pinning

Java.perform(function() {
    console.log("[*] Universal SSL Pinning Bypass — Initialisation...");

    // =========================================================
    // Étape 1 : Contourner TrustManager standard
    // =========================================================
    var TrustManager = Java.registerClass({
        name: "com.redteam.bypass.TrustManager",
        implements: [Java.use("javax.net.ssl.X509TrustManager")],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    var TrustManagers = [TrustManager.$new()];
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    var SSLContextInit = SSLContext.init.overload(
        "[Ljavax.net.ssl.KeyManager;",
        "[Ljavax.net.ssl.TrustManager;",
        "java.security.SecureRandom"
    );

    SSLContextInit.implementation = function(keyManager, trustManager, secureRandom) {
        console.log("[+] SSLContext.init() bypassé");
        SSLContextInit.call(this, keyManager, TrustManagers, secureRandom);
    };

    // =========================================================
    // Étape 2 : Contourner OkHttp (bibliothèque HTTP très répandue)
    // =========================================================
    try {
        var OkHttpClientBuilder = Java.use("okhttp3.OkHttpClient$Builder");

        OkHttpClientBuilder.hostnameVerifier.implementation = function(hostnameVerifier) {
            console.log("[+] OkHttp hostnameVerifier bypassé");
            return this;
        };

        OkHttpClientBuilder.sslSocketFactory.implementation = function(sslSocketFactory, trustManager) {
            console.log("[+] OkHttp sslSocketFactory bypassé");
            return this;
        };

        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function(hostname, peerCertificates) {
            console.log("[+] CertificatePinner.check bypassé: " + hostname);
            return;
        };
    } catch(e) {
        console.log("[-] OkHttp non trouvé: " + e);
    }

    // =========================================================
    // Étape 3 : Contourner TrustManager (Java standard)
    // =========================================================
    try {
        var X509TrustManagerExt = Java.use("javax.net.ssl.X509TrustManager");

        X509TrustManagerExt.checkServerTrusted.overload(
            "[Ljava.security.cert.X509Certificate;", "java.lang.String"
        ).implementation = function(chain, authType) {
            console.log("[+] X509TrustManager.checkServerTrusted bypassé");
        };

        var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
        HostnameVerifier.verify.overload(
            "java.lang.String", "javax.net.ssl.SSLSession"
        ).implementation = function(hostname, session) {
            console.log("[+] HostnameVerifier bypassé: " + hostname);
            return true;
        };
    } catch(e) {
        console.log("[-] TrustManager standard non trouvé: " + e);
    }

    console.log("[*] Universal SSL Pinning Bypass — Prêt");
});
```

```bash
# Exécution du bypass SSL Pinning
frida -U -l universal_ssl_pinning_bypass.js -f com.example.vulnapp --no-pause
```

### 2.4 Bypass Root Detection (T1406)

```javascript
// root_bypass.js — Bypass de détection de root Android
// T1406 — Contournement des mécanismes de détection

Java.perform(function() {
    console.log("[*] Root Detection Bypass — Initialisation...");

    // =========================================================
    // Méthode 1 : Hooker File.exists()
    // =========================================================
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        var rootPaths = ["su", "busybox", "magisk", "supersu", "superuser"];

        for (var i = 0; i < rootPaths.length; i++) {
            if (path.toLowerCase().indexOf(rootPaths[i]) >= 0) {
                console.log("[+] File.exists() bypassé pour: " + path);
                return false; // Le fichier "n'existe pas"
            }
        }

        return this.exists(); // Comportement normal pour les autres fichiers
    };

    // =========================================================
    // Méthode 2 : Hooker Runtime.exec() — empêcher l'exécution de "which su"
    // =========================================================
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload("[Ljava/lang.String;").implementation = function(cmd) {
        if (cmd[0].indexOf("su") >= 0 || cmd[0].indexOf("which") >= 0) {
            console.log("[+] Runtime.exec() bypassé: " + cmd[0]);
            throw Java.use("java.io.IOException").$new("Command not found");
        }
        return this.exec(cmd);
    };

    Runtime.exec.overload("java.lang.String").implementation = function(cmd) {
        if (cmd.indexOf("su") >= 0 || cmd.indexOf("which") >= 0) {
            console.log("[+] Runtime.exec(String) bypassé: " + cmd);
            throw Java.use("java.io.IOException").$new("Command not found");
        }
        return this.exec(cmd);
    };

    // =========================================================
    // Méthode 3 : Hooker System.getProperty() pour Build.TAGS
    // =========================================================
    var System = Java.use("java.lang.System");
    System.getProperty.overload("java.lang.String").implementation = function(key) {
        if (key === "ro.build.tags") {
            console.log("[+] Build.TAGS bypassé → release-keys");
            return "release-keys";
        }
        if (key === "ro.debuggable") {
            console.log("[+] ro.debuggable bypassé → 0");
            return "0";
        }
        return this.getProperty(key);
    };

    // =========================================================
    // Méthode 4 : Hooker PackageManager — cacher les apps root
    // =========================================================
    try {
        var PackageManager = Java.use("android.content.pm.PackageManager");
        PackageManager.getPackageInfo.overload("java.lang.String", "int").implementation = function(packageName, flags) {
            var rootApps = ["com.noshufou.android.su", "com.topjohnwu.magisk",
                           "eu.chainfire.supersu", "com.koushikdutta.superuser"];

            if (rootApps.indexOf(packageName) >= 0) {
                console.log("[+] PackageManager bypassé: " + packageName);
                throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new();
            }
            return this.getPackageInfo(packageName, flags);
        };
    } catch(e) {
        console.log("[-] PackageManager hook non nécessaire: " + e);
    }

    console.log("[*] Root Detection Bypass — Prêt");
});
```

```bash
# Lancer le bypass root detection
frida -U -l root_bypass.js -f com.example.vulnapp --no-pause
```

### 2.5 Bypass Emulator Detection (T1406)

```javascript
// emulator_bypass.js — Contourne la détection d'émulateur
// T1406

Java.perform(function() {
    console.log("[*] Emulator Detection Bypass — Initialisation...");

    // Méthode 1 : Hooker Build.FINGERPRINT
    var Build = Java.use("android.os.Build");
    var BuildClass = Build.class;
    var FingerprintField = BuildClass.getDeclaredField("FINGERPRINT");
    FingerprintField.setAccessible(true);
    var originalFingerprint = FingerprintField.get(null);
    console.log("[*] Build.FINGERPRINT original: " + originalFingerprint);

    // Méthode 2 : Hooker les propriétés système émulées
    var System = Java.use("java.lang.System");
    System.getProperty.overload("java.lang.String").implementation = function(key) {
        var emulatorProps = {
            "ro.kernel.qemu": "0",
            "ro.kernel.qemu.gles": "0",
            "init.svc.adbd": null,
            "qemu.hw.mainkeys": "1",
            "ro.hardware": "qcom",
            "ro.product.brand": "samsung",
            "ro.product.device": "dream2qlte",
            "ro.product.manufacturer": "samsung",
            "ro.product.model": "SM-G955F",
            "ro.bootloader": "G955FXXU1AQF7",
            "ro.build.user": "dpi"
        };

        if (key in emulatorProps) {
            var value = emulatorProps[key];
            console.log("[+] System.getProperty bypassé: " + key + " → " + value);
            return value;
        }
        return this.getProperty(key);
    };

    // Méthode 3 : Hooker TelephonyManager
    try {
        var TelephonyManager = Java.use("android.telephony.TelephonyManager");
        TelephonyManager.getDeviceId.implementation = function() {
            console.log("[+] TelephonyManager.getDeviceId bypassé");
            return "358240051111110"; // IMEI légitime
        };
        TelephonyManager.getNetworkOperatorName.implementation = function() {
            console.log("[+] TelephonyManager.getNetworkOperatorName bypassé");
            return "Orange";
        };
        TelephonyManager.getSimSerialNumber.implementation = function() {
            console.log("[+] TelephonyManager.getSimSerialNumber bypassé");
            return "89014103211118510720";
        };
    } catch(e) {
        console.log("[-] TelephonyManager non trouvé: " + e);
    }

    console.log("[*] Emulator Detection Bypass — Prêt");
});
```

```bash
# Lancer le bypass
frida -U -l emulator_bypass.js -f com.example.vulnapp --no-pause
```

### 2.6 Bypass Certificate Pinning avancé (T1406)

Les techniques avancées de bypass de certificate pinning ciblent les implémentations custom que l'on trouve dans les applications professionnelles.

```javascript
// advanced_pinning_bypass.js — Bypass avancé multi-approches

Java.perform(function() {
    console.log("[*] Advanced SSL Pinning Bypass");

    // =========================================================
    // Cible 1 : TrustKit (utilisé par Airbnb, Dropbox, etc.)
    // =========================================================
    try {
        var TrustKit = Java.use("com.datatheorem.android.trustkit.TrustKit");
        TrustKit.getInstance.implementation = function() {
            console.log("[+] TrustKit.getInstance bypassé");
            return null;
        };
    } catch(e) {}

    // =========================================================
    // Cible 2 : TrustManager Android (Network Security Config)
    // =========================================================
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, hostname, clientAuth, hostnameVerifiable) {
            console.log("[+] TrustManagerImpl.verifyChain bypassé: " + hostname);
            return untrustedChain;
        };
    } catch(e) {}

    // =========================================================
    // Cible 3 : Retrofit + OkHttp (très répandu)
    // =========================================================
    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        var RealCall = Java.use("okhttp3.internal.connection.RealCall");
        RealCall.execute.implementation = function() {
            console.log("[+] RealCall.execute intercepté");
            return this.execute();
        };
    } catch(e) {}

    // =========================================================
    // Cible 4 : Apache HttpClient (ancien)
    // =========================================================
    try {
        var DefaultHttpClient = Java.use("org.apache.http.impl.client.DefaultHttpClient");
        console.log("[!] Apache HttpClient détecté — application ancienne");
    } catch(e) {}

    // =========================================================
    // Cible 5 : Cronet (Google Chromium network stack)
    // =========================================================
    try {
        var CronetEngine = Java.use("org.chromium.net.impl.CronetUrlRequestContext");
        console.log("[+] Cronet détecté");
    } catch(e) {}

    // =========================================================
    // Cible 6 : WebView SSL Error Handler
    // =========================================================
    try {
        var SslErrorHandler = Java.use("android.webkit.SslErrorHandler");
        SslErrorHandler.proceed.implementation = function() {
            console.log("[+] SslErrorHandler.proceed()");
            return this.proceed();
        };
        SslErrorHandler.cancel.implementation = function() {
            console.log("[!] SslErrorHandler.cancel() bloqué → proceed()");
            return this.proceed();
        };
    } catch(e) {}

    console.log("[*] Advanced SSL Pinning Bypass — Prêt");
});
```

---

## 3. Analyse de stockage local (T1407)

L'analyse du stockage local est essentielle car les applications mobiles stockent souvent des données sensibles de manière insécurisée.

```
┌──────────────────────────────────────────────────────────────┐
│       EMPLACEMENTS DE STOCKAGE LOCAL ANDROID                  │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  /data/data/<package>/                           (Internal)   │
│  ├── shared_prefs/          ← SharedPreferences (XML)        │
│  │   └── *.xml                                                │
│  ├── databases/             ← SQLite databases               │
│  │   └── *.db, *.db-journal                                   │
│  ├── files/                 ← Fichiers internes              │
│  │   └── *                                                     │
│  ├── cache/                 ← Cache temporaire                │
│  │   └── *                                                     │
│  └── code_cache/            ← Cache ART/Dalvik               │
│                                                               │
│  /sdcard/Android/data/<package>/                (External)   │
│  ├── files/                 ← Fichiers externes              │
│  └── cache/                 ← Cache externe                  │
│                                                               │
│  /sdcard/Download/                         (Stockage public) │
│  /sdcard/Documents/                                          │
│  /sdcard/Pictures/                                            │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

### 3.1 SharedPreferences — données en clair (T1407)

`SharedPreferences` est le mécanisme de stockage clé-valeur le plus simple sur Android. Il stocke les données dans des fichiers XML dans `/data/data/<package>/shared_prefs/`. Si le mode `MODE_WORLD_READABLE` ou `MODE_WORLD_WRITEABLE` est utilisé (déprécié mais encore présent), toute application peut y accéder.

```bash
# Étape 1 : Lister les SharedPreferences
adb shell "run-as com.example.vulnapp ls -la shared_prefs/"
# ou si root :
adb shell "ls -la /data/data/com.example.vulnapp/shared_prefs/"

# Étape 2 : Lire les fichiers XML de préférences
adb shell "cat /data/data/com.example.vulnapp/shared_prefs/*.xml"

# Étape 3 : Copier sur le PC pour analyse
adb shell "cp /data/data/com.example.vulnapp/shared_prefs/*.xml /sdcard/"
adb pull /sdcard/MyPrefs.xml ./
```

**Exemple de contenu SharedPreferences vulnérable :**

```xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <!-- ⚠️ T1407: Token d'authentification en clair -->
    <string name="auth_token">eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...</string>

    <!-- ⚠️ T1407: Identifiants stockés -->
    <string name="username">admin@divabank.com</string>
    <string name="password">P@ssw0rd!2024</string>

    <!-- ⚠️ T1407: Clé API en clair -->
    <string name="api_key">AIzaSyDummyApiKeyForDivaApp1234567</string>

    <!-- ⚠️ T1407: Données de session -->
    <string name="session_id">sess_1234567890abcdef</string>
    <boolean name="is_premium" value="true" />

    <!-- URL de serveur interne -->
    <string name="server_url">https://api.internal.divabank.com/v2/</string>
</map>
```

**Avec Objection :**

```bash
# Depuis le prompt Objection
android sharedpreferences list
# → Affiche tous les fichiers SP

android sharedpreferences get com.example.vulnapp_preferences auth_token
# → Récupère la valeur d'une clé spécifique

android sharedpreferences set com.example.vulnapp_preferences is_premium true
# → MODIFIE une valeur (persistance !)
```

### 3.2 Bases de données SQLite — extraction (T1407)

Les applications Android utilisent SQLite pour le stockage structuré. Les fichiers `.db` se trouvent dans `/data/data/<package>/databases/`.

```bash
# Étape 1 : Lister les bases de données
adb shell "ls -la /data/data/com.example.vulnapp/databases/"

# Étape 2 : Extraire le fichier .db
adb shell "cp /data/data/com.example.vulnapp/databases/app.db /sdcard/app.db"
adb pull /sdcard/app.db ./

# Étape 3 : Explorer la base de données
sqlite3 app.db

sqlite> .tables                          # Lister les tables
# Output : android_metadata  users  transactions  secrets

sqlite> .schema users                    # Voir la structure
# CREATE TABLE users (
#   id INTEGER PRIMARY KEY AUTOINCREMENT,
#   username TEXT,
#   password TEXT,          ← ⚠️ T1407: mots de passe en clair !
#   email TEXT,
#   token TEXT              ← ⚠️ T1407: tokens de session
# );

sqlite> SELECT * FROM users;             # Extraire toutes les données

sqlite> .dump                            # Dump complet de la BDD

sqlite> .quit

# Étape 4 : Recherche avancée dans les BDDs
# Trouver toutes les bases de données sur le device
adb shell "find /data/data -name '*.db' 2>/dev/null" | head -20

# Extraire en masse
for pkg in $(adb shell pm list packages -3 | cut -d: -f2); do
    adb shell "run-as $pkg ls databases/ 2>/dev/null" && echo "=== $pkg ==="
done
```

**Avec Objection :**

```bash
# Depuis Objection
android sqlite list
# → Liste toutes les BDD de l'application

android sqlite connect /data/data/com.example.vulnapp/databases/app.db
sqlite> .tables
sqlite> SELECT sql FROM sqlite_master WHERE type='table';
sqlite> SELECT * FROM users WHERE username LIKE '%admin%';
sqlite> .quit
```

**Avec Frida (script pour dumper SQLite) :**

```javascript
// sqlite_dump.js — Hooker SQLiteDatabase pour intercepter les requêtes
// T1407

Java.perform(function() {
    var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");

    // Hooker rawQuery
    SQLiteDatabase.rawQuery.overload("java.lang.String", "[Ljava.lang.String;").implementation = function(sql, selectionArgs) {
        console.log("[SQL QUERY] " + sql);
        if (selectionArgs) {
            console.log("[SQL ARGS] " + JSON.stringify(selectionArgs));
        }
        return this.rawQuery(sql, selectionArgs);
    };

    // Hooker execSQL
    SQLiteDatabase.execSQL.overload("java.lang.String").implementation = function(sql) {
        console.log("[SQL EXEC] " + sql);
        return this.execSQL(sql);
    };

    // Hooker insert
    SQLiteDatabase.insert.overload("java.lang.String", "java.lang.String", "android.content.ContentValues").implementation = function(table, nullColumnHack, values) {
        console.log("[SQL INSERT] Table: " + table + " Values: " + values);
        return this.insert(table, nullColumnHack, values);
    };

    console.log("[*] SQLite hooks installés");
});
```

### 3.3 Internal/External Storage — fichiers sensibles (T1407)

```bash
# Explorer le stockage interne de l'application
adb shell "ls -laR /data/data/com.example.vulnapp/files/"
adb shell "ls -laR /data/data/com.example.vulnapp/cache/"

# Explorer le stockage externe
adb shell "ls -laR /sdcard/Android/data/com.example.vulnapp/"

# Chercher des fichiers sensibles par extension et nom
adb shell "find /data/data/com.example.vulnapp -type f -name '*.txt' -o -name '*.json' -o -name '*.xml' -o -name '*.conf' 2>/dev/null"

# Chercher des backups
adb shell "find /data/data/com.example.vulnapp -name '*backup*' -o -name '*bak*' 2>/dev/null"

# Lire les logs applicatifs
adb shell "cat /data/data/com.example.vulnapp/files/logs/*.log" 2>/dev/null

# Extraire tout le dossier data pour analyse offline
adb shell "tar -czf /sdcard/app_data.tar.gz /data/data/com.example.vulnapp 2>/dev/null"
adb pull /sdcard/app_data.tar.gz ./
tar -xzf app_data.tar.gz
```

**Script d'exploration automatisée :**

```bash
#!/bin/bash
# explore_storage.sh — Exploration du stockage d'une app (T1407)
PACKAGE=$1
echo "[*] Exploration de $PACKAGE"

echo ""
echo "=== SharedPreferences ==="
adb shell "ls -la /data/data/$PACKAGE/shared_prefs/ 2>/dev/null"

echo ""
echo "=== Bases de données ==="
adb shell "ls -la /data/data/$PACKAGE/databases/ 2>/dev/null"

echo ""
echo "=== Fichiers internes ==="
adb shell "find /data/data/$PACKAGE/files -type f 2>/dev/null"

echo ""
echo "=== Cache ==="
adb shell "find /data/data/$PACKAGE/cache -type f 2>/dev/null"

echo ""
echo "=== Stockage externe ==="
adb shell "find /sdcard/Android/data/$PACKAGE -type f 2>/dev/null"

echo ""
echo "=== Fichiers sensibles potentiels (.pem, .p12, .key, .jks) ==="
adb shell "find /data/data/$PACKAGE -type f \( -name '*.pem' -o -name '*.p12' -o -name '*.key' -o -name '*.jks' -o -name '*.keystore' -o -name '*.cer' \) 2>/dev/null"
```

### 3.4 Keystore / Keychain — fuites de clés (T1412)

Android Keystore est le mécanisme sécurisé de stockage de clés cryptographiques, adossé au TEE (Trusted Execution Environment). Cependant, une mauvaise utilisation peut mener à des fuites.

```bash
# Vérifier l'utilisation du Keystore via le code décompilé
grep -r "KeyStore\|KeyChain\|KeyPairGenerator\|KeyGenerator" jadx_output/sources/

# Avec Objection, lister les entrées du Keystore
android keystore list
```

```java
// Exemple de code vulnérable avec Keystore

// ⚠️ T1412 : Mauvais usage — alias et protection faibles
KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
ks.load(null);

// ⚠️ Alias prévisible
SecretKey key = (SecretKey) ks.getKey("my_master_key", null);

// ⚠️ Pas de vérification de biométrie/pin avant accès
// ⚠️ Pas de paramètre setUserAuthenticationRequired(true)

// CORRECT :
KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
    "my_master_key",
    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
    .setUserAuthenticationRequired(true)    // ← Exiger biométrie
    .setUserAuthenticationValidityDurationSeconds(60)
    .build();
```

**Avec Frida — intercepter l'utilisation du Keystore :**

```javascript
// keystore_monitor.js — Surveiller l'accès au Keystore
// T1407 — T1412

Java.perform(function() {
    var KeyStore = Java.use("java.security.KeyStore");

    // Hooker KeyStore.load()
    KeyStore.load.overload("java.io.InputStream", "[C").implementation = function(stream, password) {
        console.log("[KEYSTORE] load() appelé");
        if (password) {
            console.log("[KEYSTORE] Password: " + password);
        }
        return this.load(stream, password);
    };

    // Hooker KeyStore.getKey()
    KeyStore.getKey.overload("java.lang.String", "[C").implementation = function(alias, password) {
        console.log("[KEYSTORE] getKey() — Alias: " + alias);
        var key = this.getKey(alias, password);
        if (key) {
            console.log("[KEYSTORE] Clé récupérée: " + key.getAlgorithm() + " " + key.getFormat());
        }
        return key;
    };

    console.log("[*] Keystore monitor actif");
});
```

---

## 4. Analyse réseau avancée (T1040)

### 4.1 Interception HTTPS avec certificat injecté

L'interception HTTPS avancée nécessite de surmonter le certificate pinning. Une fois le bypass en place, on peut analyser tout le trafic.

```bash
# Workflow complet d'interception HTTPS avancée :

# 1. Lancer Burp Suite et configurer le proxy
burpsuite &

# 2. Lancer le bypass SSL Pinning avec Frida
frida -U -l universal_ssl_pinning_bypass.js -f com.example.vulnapp --no-pause

# 3. Configurer le proxy système Android
adb shell settings put global http_proxy 10.0.2.2:8080

# 4. Dans Burp, activer l'interception
# Proxy → Intercept → Intercept is on

# 5. Interagir avec l'application, observer le trafic
```

### 4.2 Analyse des API calls — Patterns, tokens, auth headers (T1040)

```bash
# Dans Burp, après avoir capturé le trafic :

# Onglet "Proxy" → "HTTP history"
# → Filtrer par host, status code, MIME type

# Analyser les requêtes d'authentification :
# - Chercher POST /login, POST /auth, POST /token
# - Examiner les headers Authorization, Cookie, X-Api-Key
# - Vérifier si les tokens JWT sont bien signés

# Analyser les réponses :
# - Chercher les réponses 200 avec données sensibles (JSON, XML)
# - Vérifier les headers CORS (Access-Control-Allow-Origin: *)
# - Vérifier la présence de Server, X-Powered-By (fuite d'information)
```

**Patterns d'authentification à rechercher :**

```
┌──────────────────────────────────────────────────────────────┐
│  PATTERNS D'AUTHENTIFICATION À ANALYSER                      │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  Type              Header/Pattern          Risque             │
│  ──────────────    ──────────────────      ─────────────     │
│  Bearer Token     Authorization: Bearer    Token JWT mal     │
│                    eyJhbGciOi...           configuré          │
│                                                               │
│  Basic Auth       Authorization: Basic    Base64 décodable   │
│                    dXNlcjpwYXNz           facilement          │
│                                                               │
│  API Key          X-Api-Key: abc123       Clé en clair       │
│                   ?api_key=abc123         dans l'URL          │
│                                                               │
│  Session Cookie   Cookie: session=xyz     Vol de session      │
│                                                               │
│  OAuth 2.0        POST /oauth/token       Mauvaise gestion    │
│                    grant_type=password    des refresh tokens  │
│                                                               │
│  Custom           X-App-Token: xyz        Token prévisible    │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

**Analyse de token JWT avec Burp :**

```bash
# Dans Burp, utiliser l'onglet Decoder :
# 1. Copier le token JWT (partie entre les points)
# 2. Decoder → Base64 decode
# 3. Vérifier l'algorithme (HS256, RS256, none ?)
# 4. Vérifier les claims (exp, iat, sub, role, etc.)

# Exemple de JWT décodé :
# Header : {"alg":"HS256","typ":"JWT"}
# Payload : {"sub":"user123","role":"user","exp":1745100000}
# ⚠️ Si "role":"user" → tenter de le changer en "admin"
```

### 4.3 Détection et bypass de Certificate Pinning

Techniques de détection de certificate pinning dans le code :

```bash
# Rechercher les implémentations de pinning dans le code décompilé
grep -r "CertificatePinner\|TrustKit\|SSLPinning\|certificatePinner" jadx_output/
grep -r "pinning\|sha256\|public key" jadx_output/sources/
grep -r "network_security_config" jadx_output/resources/

# Rechercher les fingerprints de certificats hardcodés
grep -rE 'sha256\/[A-Za-z0-9+\/=]{44}' jadx_output/sources/
```

**Contournement via Network Security Config :**

```bash
# Si l'app utilise network_security_config.xml, on peut le modifier :

# 1. Trouver la config réseau
cat cible_apktool/res/xml/network_security_config.xml

# 2. Contenu original :
# <network-security-config>
#   <domain-config>
#     <domain includeSubdomains="true">api.example.com</domain>
#     <pin-set>
#       <pin digest="SHA-256">sha256/AAAAAA...</pin>
#     </pin-set>
#   </domain-config>
# </network-security-config>

# 3. Patch — Supprimer le pin-set :
# <network-security-config>
#   <domain-config>
#     <domain includeSubdomains="true">api.example.com</domain>
#     <trust-anchors>
#       <certificates src="system" />
#       <certificates src="user" />
#     </trust-anchors>
#   </domain-config>
# </network-security-config>

# 4. Recompiler l'APK avec apktool b
```

---

## 5. TP Guidé — Analyse dynamique complète

### 5.1 Contexte du TP

```
┌──────────────────────────────────────────────────────────────┐
│              TP GUIDÉ — SCÉNARIO                              │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  Mission : Auditer l'application "DivaVault" qui stocke       │
│  des secrets d'entreprise. L'application a subi une           │
│  analyse statique (Module 11) qui a révélé des endpoints      │
│  API et des secrets hardcodés. Vous devez maintenant          │
│  réaliser l'analyse dynamique complète.                       │
│                                                               │
│  Objectifs :                                                  │
│  1. Identifier et bypasser les protections (root, emulator)   │
│  2. Hooker les fonctions critiques avec Frida                 │
│  3. Intercepter et analyser le trafic réseau                  │
│  4. Extraire les données sensibles du stockage local          │
│  5. Documenter les vulnérabilités avec MITRE ATT&CK           │
│                                                               │
│  Durée estimée : 45 minutes                                   │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

### 5.2 Phase 1 — Setup et patching (10 min)

```bash
# ============================================================
# Étape 1.1 : Préparer l'environnement
# ============================================================
cd ~/pentest-mobile/tp2
mkdir -p patched frida_scripts loot

# Vérifier l'émulateur
adb devices
adb root && adb remount

# ============================================================
# Étape 1.2 : Démarrer frida-server
# ============================================================
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server -D &"

# Vérifier
frida-ps -U

# ============================================================
# Étape 1.3 : Décompiler l'APK cible
# ============================================================
wget -O vault.apk https://example.com/vault.apk 2>/dev/null || \
  cp ~/pentest-mobile/tp1/cible.apk vault.apk

apktool d vault.apk -o vault_apktool -f
jadx -d vault_jadx vault.apk

# ============================================================
# Étape 1.4 : Identifier les protections dans le code
# ============================================================
echo "=== Protections détectées ==="

grep -r "isRooted\|isDeviceRooted\|checkRoot\|rootDetection" vault_jadx/sources/
grep -r "isEmulator\|checkEmulator\|emulatorCheck" vault_jadx/sources/
grep -r "SSLPinning\|CertificatePinner\|pinning" vault_jadx/sources/
grep -r "frida\|Xposed\|substrate\|tampering" vault_jadx/sources/

# ============================================================
# Étape 1.5 : Patcher le contournement de root
# ============================================================
# Localiser le fichier smali de RootDetection
find vault_apktool/smali -name "*.smali" | xargs grep -l "isDeviceRooted\|isRooted" 2>/dev/null

# Éditer le fichier pour forcer le retour à false
# Exemple avec sed (remplacement rapide)
ROOT_FILE=$(find vault_apktool/smali -name "*.smali" | xargs grep -l "isDeviceRooted" 2>/dev/null | head -1)
echo "Fichier à patcher : $ROOT_FILE"

# Appliquer le patch (remplacer la méthode complète)
# Voir section 1.2.1 pour le code smali exact du patch

# ============================================================
# Étape 1.6 : Recompiler et installer l'APK patchée
# ============================================================
apktool b vault_apktool -o vault_patched.apk

# Signer
~/Android/Sdk/build-tools/34.0.0/apksigner sign \
    --ks ~/pentest-mobile/my-release-key.keystore \
    --ks-pass pass:password123 \
    --key-pass pass:password123 \
    --ks-key-alias pentest_alias \
    vault_patched.apk

# Installer
adb install vault_patched.apk
```

### 5.3 Phase 2 — Instrumentation Frida (15 min)

```javascript
// tp_hooks.js — Script Frida pour le TP
// Sauvegarder dans frida_scripts/tp_hooks.js

Java.perform(function() {
    console.log("[=== TP Analyse dynamique - Hooks actifs ===]");

    // Hook 1 : Intercepter l'authentification
    try {
        var LoginActivity = Java.use("com.example.vault.LoginActivity");
        LoginActivity.validateCredentials.implementation = function(username, password) {
            console.log("[+] LOGIN: " + username + " / " + password);
            var result = this.validateCredentials(username, password);
            console.log("[+] RESULT: " + result);
            return result;
        };
    } catch(e) {
        console.log("[-] LoginActivity non trouvé: " + e);
    }

    // Hook 2 : Intercepter les appels API
    try {
        var ApiClient = Java.use("com.example.vault.network.ApiClient");
        var methods = ApiClient.class.getDeclaredMethods();
        methods.forEach(function(method) {
            var methodName = method.getName();
            console.log("[*] Méthode API trouvée: " + methodName);
        });
    } catch(e) {}

    // Hook 3 : Détecter l'écriture dans SharedPreferences
    try {
        var Editor = Java.use("android.content.SharedPreferences$Editor");
        Editor.putString.implementation = function(key, value) {
            console.log("[SP PUT] " + key + " = " + value);
            return this.putString(key, value);
        };
    } catch(e) {}

    // Hook 4 : Intercepter les opérations cryptographiques
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.doFinal.overload("[B").implementation = function(input) {
            console.log("[CIPHER] doFinal appelé, longueur entrée: " + input.length);
            var result = this.doFinal(input);
            return result;
        };
    } catch(e) {}

    console.log("[=== Hooks installés ===]");
});
```

```bash
# Lancer l'application avec les hooks Frida
frida -U -l frida_scripts/tp_hooks.js -f com.example.vault --no-pause
```

### 5.4 Phase 3 — Interception réseau (10 min)

```bash
# ============================================================
# Étape 3.1 : Configurer Burp
# ============================================================
# Proxy → Options → Proxy Listeners → Add
# Port 8080, All interfaces

# ============================================================
# Étape 3.2 : Lancer le bypass SSL Pinning
# ============================================================
# Dans un autre terminal :
frida -U -l universal_ssl_pinning_bypass.js -f com.example.vault --no-pause

# ============================================================
# Étape 3.3 : Configurer le proxy Android
# ============================================================
adb shell settings put global http_proxy 10.0.2.2:8080

# ============================================================
# Étape 3.4 : Intercepter et analyser le trafic
# ============================================================
# Interagir avec l'application :
# - Se connecter
# - Naviguer entre les écrans
# - Effectuer toutes les actions disponibles

# Dans Burp, analyser :
# - HTTP history : tous les endpoints
# - WebSockets history : connexions persistantes
# - Examiner chaque requête POST/PUT contenant des données

# ============================================================
# Étape 3.5 : Checklist d'analyse réseau
# ============================================================
echo "=== Checklist analyse réseau ==="
echo "1. Endpoints API découverts :"
echo "2. Méthode d'authentification :"
echo "3. Tokens/Sessions utilisés :"
echo "4. Données sensibles en clair (HTTP) :"
echo "5. Headers d'information (Server, X-Powered-By) :"
echo "6. CORS configuration :"
echo "7. Rate limiting présent :"
```

### 5.5 Phase 4 — Extraction de données (10 min)

```bash
# ============================================================
# Étape 4.1 : Extraire les SharedPreferences
# ============================================================
adb shell "cat /data/data/com.example.vault/shared_prefs/*.xml" > loot/shared_prefs.xml
cat loot/shared_prefs.xml

# Analyser :
# - Tokens d'authentification stockés ?
# - Mots de passe en clair ?
# - URLs de serveur ?
# - Clés API ?

# ============================================================
# Étape 4.2 : Extraire les bases de données SQLite
# ============================================================
for db in $(adb shell "ls /data/data/com.example.vault/databases/*.db" 2>/dev/null); do
    db_name=$(basename $db)
    adb shell "cp $db /sdcard/$db_name"
    adb pull /sdcard/$db_name loot/
    echo "=== Contenu de $db_name ==="
    sqlite3 loot/$db_name .tables
    sqlite3 loot/$db_name .dump
done

# ============================================================
# Étape 4.3 : Extraire les fichiers du stockage interne
# ============================================================
adb shell "find /data/data/com.example.vault/files -type f" > loot/file_list.txt
cat loot/file_list.txt

for file in $(cat loot/file_list.txt); do
    adb shell "cat $file" 2>/dev/null
done

# ============================================================
# Étape 4.4 : Extraire les logs
# ============================================================
adb logcat -d | grep -i "vault" > loot/logcat.txt
cat loot/logcat.txt | grep -i "error\|exception\|password\|token\|secret\|key"
```

### 5.6 Rapport — Cartographie MITRE ATT&CK

```markdown
### Rapport de pentest mobile dynamique — DivaVault

#### Vulnérabilité 1 : Absence de Certificate Pinning
- **Gravité** : Élevé
- **Technique MITRE** : T1040 — Network Traffic Interception
- **Description** : Aucune vérification de certificat, trafic HTTPS interceptable
- **Preuve** : Capture Burp complète de toutes les requêtes
- **Impact** : Vol de tokens, mots de passe, données métier

#### Vulnérabilité 2 : Détection root contournable
- **Gravité** : Élevé
- **Technique MITRE** : T1406 — Root Detection Bypass
- **Description** : La détection de root est contournable par patching smali
- **Preuve** : APK patchée exécutée avec succès sur device rooté
- **Impact** : L'application fonctionne sur un device compromis

#### Vulnérabilité 3 : Secrets hardcodés (confirmé dynamiquement)
- **Gravité** : Critique
- **Technique MITRE** : T1407 — Hardcoded Credentials
- **Description** : Clés API et secrets interceptés dans le trafic réseau
- **Preuve** : Token `AIzaSy...` capturé dans Burp
- **Impact** : Accès non autorisé à l'API backend

#### Vulnérabilité 4 : Stockage insécurisé de tokens
- **Gravité** : Critique
- **Technique MITRE** : T1407 — SharedPreferences in Plaintext
- **Description** : Token JWT stocké en clair dans SharedPreferences
- **Preuve** : Extraction du fichier `shared_prefs/*.xml`
- **Impact** : Vol de session, usurpation d'identité

#### Vulnérabilité 5 : Base de données non chiffrée
- **Gravité** : Critique
- **Technique MITRE** : T1407 — SQLite Database Extraction
- **Description** : Mots de passe stockés en clair dans la base SQLite
- **Preuve** : `sqlite3 app.db "SELECT * FROM users"`
- **Impact** : Compromission complète des comptes utilisateurs

#### Vulnérabilité 6 : Logging de données sensibles
- **Gravité** : Moyen
- **Technique MITRE** : T1407 — Logcat Data Leakage
- **Description** : Tokens et identifiants présents dans les logs système
- **Preuve** : Extraction logcat
- **Impact** : Fuite d'information via `adb logcat`
```

### 5.7 Script de pentest automatisé (bonus)

```bash
#!/bin/bash
# auto_mobile_pentest.sh — Script automatisé de pentest mobile
# Usage : ./auto_mobile_pentest.sh <package_name> <apk_file>

PACKAGE=$1
APK=$2
OUTDIR="pentest_${PACKAGE}_$(date +%Y%m%d_%H%M%S)"

echo "[*] Pentest automatique de $PACKAGE"
mkdir -p $OUTDIR/{static,dynamic,network,storage}

# Phase 1 : Analyse statique
echo "[+] Phase 1 : Analyse statique"
apktool d $APK -o $OUTDIR/static/apktool -f
jadx -d $OUTDIR/static/jadx $APK
grep -rE 'password|secret|api[_-]?key|token' $OUTDIR/static/jadx/sources/ > $OUTDIR/static/secrets.txt
grep -rE 'https?://' $OUTDIR/static/jadx/sources/ | sort -u > $OUTDIR/static/urls.txt
grep -B2 'exported="true"' $OUTDIR/static/apktool/AndroidManifest.xml > $OUTDIR/static/exports.txt

# Phase 2 : Analyse réseau (nécessite Burp en cours d'exécution)
echo "[+] Phase 2 : Interception réseau"
adb install $APK
adb shell settings put global http_proxy 10.0.2.2:8080
adb shell monkey -p $PACKAGE -c android.intent.category.LAUNCHER 1
sleep 10
echo "→ Analyser le trafic dans Burp (Proxy → HTTP history)"
echo "→ Exporter l'historique dans $OUTDIR/network/burp_history.xml"

# Phase 3 : Extraction des données
echo "[+] Phase 3 : Extraction des données"
adb shell "tar -czf /sdcard/${PACKAGE}_data.tar.gz /data/data/$PACKAGE 2>/dev/null"
adb pull /sdcard/${PACKAGE}_data.tar.gz $OUTDIR/storage/
adb shell "logcat -d | grep -i '$PACKAGE'" > $OUTDIR/storage/logcat.txt

# Phase 4 : Génération du rapport
echo "[+] Phase 4 : Génération du rapport"
cat > $OUTDIR/rapport.md << EOF
# Rapport de pentest mobile — $PACKAGE

## Résumé exécutif

## Analyse statique
- Secrets trouvés : $(wc -l < $OUTDIR/static/secrets.txt)
- URLs découvertes : $(wc -l < $OUTDIR/static/urls.txt)
- Composants exportés : $(wc -l < $OUTDIR/static/exports.txt)

## Analyse réseau
Voir $OUTDIR/network/burp_history.xml

## Analyse stockage
Données extraites dans $OUTDIR/storage/

## Cartographie MITRE ATT&CK
| Technique | ID | Vulnérabilité |
|-----------|----|---------------|
EOF

echo "[*] Pentest terminé. Résultats dans $OUTDIR/"
```

---

## 6. Références

### 6.1 Documentation officielle

- **OWASP Mobile Security Testing Guide — Reverse Engineering** : https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0014/
- **OWASP Mobile Security Testing Guide — Dynamic Analysis** : https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0015/
- **OWASP Mobile Security Testing Guide — Network** : https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0017/
- **MITRE ATT&CK Mobile — Defense Evasion (T1406)** : https://attack.mitre.org/techniques/T1406/
- **MITRE ATT&CK Mobile — Credential Access (T1407)** : https://attack.mitre.org/techniques/T1407/
- **MITRE ATT&CK Mobile — Network Sniffing (T1040)** : https://attack.mitre.org/techniques/T1040/
- **Android Security Documentation** : https://source.android.com/docs/security

### 6.2 Frida

- **Frida Documentation officielle** : https://frida.re/docs/home/
- **Frida JavaScript API** : https://frida.re/docs/javascript-api/
- **Frida CodeShare (scripts communautaires)** : https://codeshare.frida.re/
- **Frida Android Tutorial** : https://frida.re/docs/android/
- **frida-il2cpp-bridge** : https://github.com/vfsfitvnm/frida-il2cpp-bridge

### 6.3 Outils complémentaires

- **Objection** : https://github.com/sensepost/objection
- **RMS (Runtime Mobile Security)** : https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security
- **MobSF (Mobile Security Framework)** : https://github.com/MobSF/Mobile-Security-Framework-MobSF
- **APKLab (extension VSCode)** : https://github.com/APKLab/APKLab
- **Android Studio Profiler** : https://developer.android.com/studio/profile
- **pidcat** (logcat colorisé) : https://github.com/JakeWharton/pidcat
- **drozer** (framework pentest Android) : https://github.com/WithSecureLabs/drozer
- **Magisk** (root systemless) : https://github.com/topjohnwu/Magisk
- **LSPosed** (framework modules Android) : https://github.com/LSPosed/LSPosed

### 6.4 Applications vulnérables d'entraînement (niveau avancé)

- **OVAA (Oversecured Vulnerable Android App)** : https://github.com/oversecured/ovaa
- **Hera (Banking app vulnérable)** : https://github.com/sensepost/objection
- **Vuldroid** : https://github.com/jaiswalakshansh/Vuldroid
- **InjuredAndroid** : https://github.com/B3nac/InjuredAndroid
- **Allsafe** : https://github.com/t0thkr1s/allsafe
- **Damn Vulnerable Hybrid Mobile App (DVHMA)** : https://github.com/logicalhacking/DVHMA

### 6.5 Articles et techniques avancées

- **Bypassing Android SSL Pinning** : https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0012/
- **Smali Modifications for Beginners** : https://apktool.org/
- **Frida Tips & Tricks** : https://learnfrida.info/
- **Android App Reverse Engineering 101** : https://maddiestone.github.io/AndroidAppRE/
- **Mobile Hacking Workshop (BSides)** : https://mas.owasp.org/MASTG/

### 6.6 Livres recommandés

- **Android Hacker's Handbook** — Joshua Drake et al., Wiley, 2014
- **Learning Frida** — Erick Galinkin, Leanpub
- **The Mobile Security Testing Guide** — OWASP Foundation
- **Practical Binary Analysis** — Dennis Andriesse, No Starch Press

### 6.7 Cheatsheets et références rapides

```bash
# Frida Cheatsheet
frida-ps -U                          # Lister les processus
frida -U -l script.js -f com.app     # Spawn + injecter script
frida -U -n "app_name" -l script.js   # Attacher par nom
frida -U -p 1234 -l script.js        # Attacher par PID
frida-trace -U -i "open" com.app     # Tracer appels fonction native
frida-kill -U 1234                    # Tuer un processus

# Objection Cheatsheet
objection -g com.app explore         # Explorer une app
android hooking list activities       # Lister activités
android hooking list services         # Lister services
android hooking list receivers        # Lister receivers
android intent launch_activity        # Lancer activité
android sslpinning disable            # Bypass SSL Pinning
android root disable                  # Bypass Root Detection
android heap search instances <class> # Chercher instances en mémoire
```

---

> **Module précédent :** Module 11 — Introduction au Pentest Mobile (écosystème, lab, analyse statique)

> **Travail à faire après la session :**
> - Reproduire tous les patches smali sur au moins 3 applications vulnérables
> - Écrire un script Frida de bypass de détection Frida (anti-Frida bypass)
> - Réaliser un pentest complet sur OVAA (Oversecured Vulnerable Android App)
> - Préparer un rapport VAPT (Vulnerability Assessment and Penetration Testing) type client

---

*Document rédigé pour la formation M2 Red Team — SDV 2026*
*Module 12 — Reverse Engineering & Analyse Dynamique*
*Tous droits réservés*
