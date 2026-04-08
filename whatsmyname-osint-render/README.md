# 🟢 WhatsMyName OSINT — Matrix:Reloaded

Outil OSINT qui scanne **731 sites** en temps réel pour trouver les comptes liés à un nom d'utilisateur.

---

## 🚀 DÉPLOYER GRATUITEMENT SUR RENDER (5 minutes)

### Étape 1 — Créer un compte GitHub (si tu n'en as pas)
1. Va sur **https://github.com** → **Sign up**
2. Crée ton compte (email + mot de passe)

### Étape 2 — Créer un nouveau repo
1. Connecte-toi sur GitHub
2. Clique sur le **+** en haut à droite → **New repository**
3. Nom : `whatsmyname-osint`
4. Laisse en **Public**
5. Clique **Create repository**

### Étape 3 — Uploader les fichiers
1. Sur la page de ton repo vide, clique **"uploading an existing file"**
2. Fais glisser **TOUS les fichiers et dossiers** de ce projet dans la zone
3. Clique **Commit changes**

> ⚠️ Assure-toi que le dossier `public/` et les fichiers `Dockerfile`, `server.js`, `wmn-data.json`, `package.json` sont bien à la racine du repo.

### Étape 4 — Créer un compte Render
1. Va sur **https://render.com** → **Get Started for Free**
2. Clique **Sign in with GitHub** (plus simple)
3. Autorise l'accès

### Étape 5 — Déployer
1. Sur Render, clique **New** → **Web Service**
2. Connecte ton repo `whatsmyname-osint`
3. Render va détecter automatiquement le Dockerfile
4. Vérifie ces paramètres :
   - **Name** : `whatsmyname-matrix` (ou ce que tu veux)
   - **Region** : `Frankfurt` (le plus proche de la France)
   - **Instance Type** : `Free`
5. Clique **Create Web Service**
6. Attends 2-3 minutes que ça build...
7. ✅ Ton site est en ligne ! L'URL sera du type `https://whatsmyname-matrix.onrender.com`

---

## ⚠️ Limitations du plan gratuit Render
- Le serveur **s'éteint après 15 min d'inactivité** → il se rallume en ~30 sec quand quelqu'un visite
- **750 heures gratuites/mois** → suffisant pour un usage normal
- Les scans peuvent être plus lents que sur un VPS payant

---

## 🛠️ Usage
1. Ouvre ton URL Render
2. Tape un nom d'utilisateur dans la barre de recherche
3. Appuie sur SCAN
4. Les résultats arrivent en temps réel
5. Clique sur un résultat vert pour ouvrir le profil
6. Utilise EXPORT CSV pour sauvegarder

---

## 📜 Crédits
Données : [WhatsMyName](https://github.com/WebBreacher/WhatsMyName) par Micah Hoffman (CC BY-SA 4.0)
