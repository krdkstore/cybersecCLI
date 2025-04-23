# 🛡️ CyberSec MultiTool CLI

**CyberSec MultiTool CLI** est une boîte à outils de cybersécurité en ligne de commande (CLI), écrite en Python, destinée aux pentesters, étudiants, enseignants, et passionnés de sécurité informatique. Elle regroupe plus de 30 fonctionnalités orientées réseau, OSINT, exploitation, crypto, ingénierie sociale, génération de payloads, et bien plus.

---

## ⚙️ Fonctionnalités principales

- **OSINT** :
  - Recherche d'infos sur une IP (`ip-info`)
  - Recherche d'utilisateur sur +25 plateformes (`user-search`)
  - WHOIS et DNS (`whois`)

- **Réseau** :
  - Sniffer de paquets (Scapy)
  - Scanner de ports TCP
  - Détection de spoofing ARP
  - Balayage ICMP (ping sweep)

- **Exploitation** :
  - Fuzzer HTTP
  - Brute-force HTTP Basic
  - Génération de reverse shell
  - Keylogger simple et builder persistant (`build-keylogger`)

- **Crypto / Hash** :
  - Crack de hash (`md5`, `sha1`, etc.)
  - Générateur de wordlist personnalisée
  - Chiffrement/déchiffrement avec Fernet
  - Vérification de mot de passe via HaveIBeenPwned

- **Ingénierie sociale** :
  - Clonage de page HTML
  - Fenêtre de login fake
  - Raccourcisseur de lien (TinyURL)
  - Générateur de phishing mail avec pièce jointe

- **Divers** :
  - Générateur de payloads (bash/python/powershell)
  - Analyse de headers HTTP
  - Scan de sous-domaines (takeover)
  - Générateur de fausses identités
  - Encodeur/Décodeur (base64, hex, rot13, url)
  - Générateur de QR codes
  - Obfuscateur de script
  - Sniffer ARP
  - Scanner Nmap vulnérabilités

---

## 🚀 Lancer le programme

```bash
python main.py
```

Un menu interactif s'affichera avec toutes les options disponibles.

---

## 🧱 Pré-requis

Certaines fonctionnalités nécessitent les packages suivants :

```bash
pip install -r requirements.txt
```

**Exemples :**

- `scapy`
- `nmap`
- `requests`
- `cryptography`
- `faker`
- `pynput`
- `qrcode`
- `beautifulsoup4`

---

## ⚠️ Avertissement

> Ce projet est à **but éducatif** uniquement. L’auteur décline toute responsabilité en cas d’usage malveillant. Utilisez-le sur **votre propre infrastructure** ou avec **l’autorisation explicite** de la cible.

---

## 📝 Licence

Ce projet est distribué sous licence MIT.

---

## 🤝 Contribuer

Tu veux améliorer cet outil ou ajouter une fonctionnalité ? Forke le projet et propose une *pull request* !

---

## 👨‍💻 Auteur

Made with ❤️ by **KRDK**
