# Windows Setup Script

Script interactif de configuration Windows avec détection automatique, installation de logiciels et optimisation système.

## Installation

```powershell
# Télécharger le script
Invoke-WebRequest -Uri "https://github.com/LightZirconite/setup-script/raw/main/setup-windows.ps1" -OutFile "setup-windows.ps1"

# Autoriser l'exécution et lancer
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
.\setup-windows.ps1
```

## Prérequis

- Windows 10 ou Windows 11
- PowerShell 5.1+
- Droits administrateur
- Connexion internet
- Winget (App Installer) recommandé

## Fonctionnalités

### Détection Automatique
- ✅ Détecte automatiquement l'édition Windows (LTSC/IoT vs Standard)
- ✅ Active des options spécifiques selon l'édition détectée

### Mode Interactif
- ✅ Questions Y/N avec descriptions détaillées
- ✅ Collecte toutes les réponses AVANT d'installer
- ✅ Gestion d'erreurs robuste avec sortie colorée
- ✅ Vérification des privilèges administrateur

### Options d'Installation

#### Office & Activation
- Installation Microsoft Office (via winget ou téléchargement direct)
- Activation Windows/Office via Microsoft Activation Scripts

#### Logiciels (winget)
- Discord (stable, PTB, Canary)
- Steam
- Spotify
- Terminus
- Visual Studio Code
- Firefox
- Python
- Node.js

#### Gestion à Distance
- Mesh Agent (avec paramètre -fullinstall)

#### Modes de Configuration

**Mode Performance:**
- Bulk Crap Uninstaller (désinstallation profonde)
- Rytunex (optimisation système)
- Recommandation Windows LTSC

**Mode Performance + Style:**
- Tous les outils de performance
- WinPaletter (thèmes Windows)
- TranslucentTB (transparence taskbar)
- Files App (gestionnaire de fichiers moderne)
- Lively Wallpaper (optionnel)

#### Outils Spécifiques
- Steam Deck Tools (drivers et contrôle ventilateur)
- Unowhy Tools (drivers spécifiques)
- KDE Connect (connectivité appareils)

#### Options LTSC/IoT
Lorsqu'une édition LTSC/IoT est détectée:
- Activer Microsoft Store
- Installer Notepad
- Installer Windows Terminal
- Installer Calculatrice
- Installer Caméra
- Installer Media Player
- Installer Photos

#### Mises à Jour
- Mise à jour de tous les logiciels via winget

## Déroulement du Script

### 1. Phase de Détection
- Détecte l'édition Windows
- Affiche les informations système

### 2. Phase de Configuration
- Pose toutes les questions (Y/N)
- Chaque option inclut une description
- Collecte tous les choix avant de continuer

### 3. Phase d'Installation
- Traite toutes les installations sélectionnées
- Affiche la progression pour chaque étape
- Gère les erreurs avec élégance

### 4. Finalisation
- Affiche le résumé
- Propose un redémarrage système

## Détails Techniques

### Installation Office

**Méthode Winget:**
- Installation rapide via Windows Package Manager
- Intégration automatique des mises à jour

**Téléchargement Direct:**
- Télécharge depuis le CDN officiel Microsoft
- Édition O365 ProPlus Retail
- 64-bit, Anglais (US)

### Récupération des Versions
Le script récupère automatiquement les dernières versions via GitHub API pour:
- Bulk Crap Uninstaller
- Lively Wallpaper
- Steam Deck Tools
- KDE Connect

### Sécurité
- Vérification des privilèges administrateur
- Gestion complète des erreurs
- Nettoyage automatique des fichiers temporaires
- Choix par défaut sécurisés

### Code Couleur
- **Cyan** - Messages informatifs
- **Vert** - Succès
- **Jaune** - Avertissements et prompts
- **Rouge** - Erreurs

## Notes Importantes

- Certaines installations nécessitent des étapes manuelles (apps du Store)
- L'épinglage de Files App à la barre des tâches est manuel
- Le script d'activation s'ouvre dans une nouvelle fenêtre
- Redémarrage recommandé après installation
- Les utilisateurs LTSC doivent redémarrer après activation du Store

## Dépannage

**Le script ne s'exécute pas:**
```powershell
# Vérifier la politique d'exécution
Get-ExecutionPolicy

# Autoriser l'exécution
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
```

**Winget introuvable:**
- Installer "App Installer" depuis le Microsoft Store
- Ou télécharger depuis: https://github.com/microsoft/winget-cli

**Échecs de téléchargement:**
- Vérifier la connexion internet
- Vérifier les paramètres du pare-feu
- Réessayer le script

**Apps du Store ne s'installent pas:**
- S'assurer que le Microsoft Store est activé (surtout sur LTSC)
- Vérifier que Windows Update fonctionne
- Se connecter avec un compte Microsoft

## Version

**Version Actuelle:** 1.0.0

## Licence

Ce script est fourni tel quel pour la configuration de systèmes Windows.
