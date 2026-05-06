"""
TP6 - Application : Sécurisation des Communications
Sockets TCP/IP, Bluetooth, Wi-Fi/UDP, Vote électronique
"""

import socket
import ssl
import threading
import hashlib
import json
import time
from Crypto.Cipher import AES # type: ignore
from Crypto.PublicKey import RSA, ECC # type: ignore
from Crypto.Signature import DSS, pss # type: ignore
from Crypto.Hash import SHA256 # type: ignore
from Crypto.Random import get_random_bytes # type: ignore
from Crypto.Util.Padding import pad, unpad # type: ignore


# ============================================
# EXERCICE 6.1 - Sécurisation par Sockets TCP/IP
# ============================================

def secure_socket_demo():
    """
    Client/Serveur TCP sécurisé avec TLS/SSL
    """
    print("=" * 70)
    print("EXERCICE 6.1 - Sockets TCP/IP sécurisés (TLS)")
    print("=" * 70)
    
    print("""
    ARCHITECTURE CLIENT/SERVEUR TLS :
    
    Serveur                          Client
      |                                |
      |--- Certificat + Clé privée ---|
      |                                |
      |<-------- Client Hello --------|
      |-------- Server Hello -------->|
      |-------- Certificate --------->|
      |<------ Key Exchange ----------|
      |                                |
      |======= Tunnel TLS ============|
      |                                |
      |<------ Message chiffré -------|
      |------ Réponse chiffrée ------>|
    """)
    
    # Génération d'un certificat auto-signé (pour la démo)
    print("\n--- Génération du certificat ---")
    
    # Clé RSA pour le serveur
    server_key = RSA.generate(2048)
    
    # Certificat (simplifié)
    cert_info = {
        "subject": "CN=ServeurTP6,O=CyberSec,L=Paris",
        "issuer": "CN=ServeurTP6,O=CyberSec,L=Paris",
        "public_key": server_key.publickey().export_key().decode(),
        "valid_from": "2026-01-01",
        "valid_to": "2027-01-01"
    }
    
    # Signature du certificat
    cert_hash = SHA256.new(json.dumps(cert_info, sort_keys=True).encode())
    cert_signature = pss.new(server_key).sign(cert_hash)
    
    print(f"  Certificat généré (auto-signé)")
    print(f"  Signature : {cert_signature.hex()[:30]}...")
    
    # Simulation de communication sécurisée
    print(f"\n--- Simulation de communication ---")
    
    # Clé de session (échangée via TLS handshake)
    session_key = get_random_bytes(32)
    print(f"  Clé de session AES-256 : {session_key.hex()[:20]}...")
    
    # Client chiffre un message
    message = b"Message secret du client"
    iv = get_random_bytes(16)
    cipher = AES.new(session_key, AES.MODE_CBC, iv=iv)
    encrypted = cipher.encrypt(pad(message, AES.block_size))
    
    print(f"\n  Client envoie :")
    print(f"    Message : {message}")
    print(f"    IV : {iv.hex()}")
    print(f"    Chiffré : {encrypted.hex()[:40]}...")
    
    # Serveur déchiffre
    decipher = AES.new(session_key, AES.MODE_CBC, iv=iv)
    decrypted = unpad(decipher.decrypt(encrypted), AES.block_size)
    
    print(f"\n  Serveur reçoit :")
    print(f"    Déchiffré : {decrypted}")
    print(f"    Match : {message == decrypted}")
    
    # Réponse du serveur
    response = b"Accuse de reception securise"
    iv2 = get_random_bytes(16)
    cipher2 = AES.new(session_key, AES.MODE_CBC, iv=iv2)
    encrypted_response = cipher2.encrypt(pad(response, AES.block_size))
    
    print(f"\n  Serveur répond :")
    print(f"    Réponse : {response}")
    print(f"    Chiffré : {encrypted_response.hex()[:40]}...")


# ============================================
# EXERCICE 6.2 - Sécurisation Bluetooth (RFCOMM)
# ============================================

def bluetooth_security_demo():
    """
    Sécurisation Bluetooth avec pairing et chiffrement
    """
    print("\n" + "=" * 70)
    print("EXERCICE 6.2 - Sécurisation Bluetooth (RFCOMM)")
    print("=" * 70)
    
    print("""
    PAIRING BLUETOOTH (BLE/Classic) :
    
    Étape 1 : Pairing
      - Échange de clés publiques
      - Génération de clé de liaison (LTK)
      - Authentification (PIN, passkey, ou OOB)
    
    Étape 2 : Bonding
      - Stockage des clés pour futures connexions
    
    Étape 3 : Chiffrement
      - E0 (Bluetooth Classic) ou AES-CCM (BLE)
    """)
    
    # Simulation de pairing
    print("\n--- Simulation Pairing ---")
    
    # Clés éphémères
    private_a = secrets.randbelow(2**256)
    private_b = secrets.randbelow(2**256)
    
    # Clés publiques (simulées sur courbe elliptique)
    public_a = hashlib.sha256(str(private_a).encode()).hexdigest()[:32]
    public_b = hashlib.sha256(str(private_b).encode()).hexdigest()[:32]
    
    print(f"  Appareil A : clé privée = {str(private_a)[:20]}...")
    print(f"              clé publique = {public_a}")
    print(f"  Appareil B : clé privée = {str(private_b)[:20]}...")
    print(f"              clé publique = {public_b}")
    
    # Clé partagée (simulée)
    shared_secret = hashlib.sha256(
        (str(private_a) + str(private_b)).encode()
    ).digest()
    
    print(f"\n  Secret partagé : {shared_secret.hex()[:20]}...")
    
    # Chiffrement des données RFCOMM
    message = b"Donnees Bluetooth securisees"
    iv = get_random_bytes(16)
    cipher = AES.new(shared_secret[:32], AES.MODE_CBC, iv=iv)
    encrypted = cipher.encrypt(pad(message, AES.block_size))
    
    print(f"\n  Données chiffrées : {encrypted.hex()[:40]}...")
    print(f"  >>> Sécurité BLE : AES-CCM avec clé de 128 bits")


# ============================================
# EXERCICE 6.3 - Sécurisation Wi-Fi / UDP (Chat)
# ============================================

def secure_chat_demo():
    """
    Application de chat sécurisé sur UDP
    """
    print("\n" + "=" * 70)
    print("EXERCICE 6.3 - Chat sécurisé sur Wi-Fi/UDP")
    print("=" * 70)
    
    print("""
    PROTOCOLE DE CHAT SÉCURISÉ :
    
    1. ÉCHANGE DE CLÉS (Diffie-Hellman)
       Alice ---- g^a ----> Bob
       Alice <--- g^b ----- Bob
       K = g^(ab) mod p
    
    2. COMMUNICATION
       Chaque message : [IV][Chiffré][HMAC]
    
    3. INTÉGRITÉ
       HMAC-SHA256 sur chaque message
    """)
    
    # Simulation
    print("\n--- Simulation Chat Alice/Bob ---")
    
    # DH simplifié
    p = 2**256 - 2**224 + 2**192 + 2**96 - 1  # Prime de P-256
    g = 2
    
    a = secrets.randbelow(p)
    b = secrets.randbelow(p)
    
    A = pow(g, a, p)
    B = pow(g, b, p)
    
    K_alice = pow(B, a, p)
    K_bob = pow(A, b, p)
    
    # Dérivation de clés
    K_bytes = K_alice.to_bytes(32, 'big')
    enc_key = hashlib.sha256(b'enc' + K_bytes).digest()[:16]
    mac_key = hashlib.sha256(b'mac' + K_bytes).digest()[:16]
    
    print(f"  Clé de chiffrement : {enc_key.hex()[:20]}...")
    print(f"  Clé MAC : {mac_key.hex()[:20]}...")
    
    # Alice envoie un message
    messages = [
        b"Salut Bob !",
        b"Comment vas-tu ?",
        b"Message secret : password123"
    ]
    
    for msg in messages:
        iv = get_random_bytes(16)
        cipher = AES.new(enc_key, AES.MODE_CBC, iv=iv)
        encrypted = cipher.encrypt(pad(msg, AES.block_size))
        
        # HMAC
        mac = hashlib.sha256(mac_key + iv + encrypted).digest()[:16]
        
        # Paquet UDP simulé
        packet = {
            'iv': iv.hex(),
            'data': encrypted.hex(),
            'mac': mac.hex()
        }
        
        print(f"\n  Alice -> Bob : '{msg.decode()}'")
        print(f"    Paquet : {json.dumps(packet, indent=4)[:100]}...")
        
        # Bob vérifie et déchiffre
        iv_recv = bytes.fromhex(packet['iv'])
        data_recv = bytes.fromhex(packet['data'])
        mac_recv = bytes.fromhex(packet['mac'])
        
        # Vérifier MAC
        mac_check = hashlib.sha256(mac_key + iv_recv + data_recv).digest()[:16]
        if mac_check == mac_recv:
            decipher = AES.new(enc_key, AES.MODE_CBC, iv=iv_recv)
            decrypted = unpad(decipher.decrypt(data_recv), AES.block_size)
            print(f"    Bob reçoit : '{decrypted.decode()}' ✓")
        else:
            print(f"    MAC invalide ! Message rejeté ✗")


# ============================================
# EXERCICE 6.4 - Vote électronique sécurisé (Homomorphisme)
# ============================================

def homomorphic_voting_demo():
    """
    Vote électronique avec chiffrement homomorphe (Paillier simplifié)
    """
    print("\n" + "=" * 70)
    print("EXERCICE 6.4 - Vote électronique (Homomorphisme)")
    print("=" * 70)
    
    print("""
    SCHÉMA DE VOTE ÉLECTRONIQUE :
    
    Propriétés requises :
    - Confidentialité : le vote est chiffré
    - Intégrité : un seul vote par électeur
    - Vérifiabilité : l'électeur peut vérifier son vote
    - Anonymat : impossible de lier vote et électeur
    
    Homomorphisme :
    E(v1) * E(v2) = E(v1 + v2)
    Permet de compter sans déchiffrer !
    """)
    
    # Simulation simplifiée avec ElGamal (multiplicatif)
    # Pour l'addition, on utilise l'exponentielle
    
    print("\n--- Simulation de vote ---")
    
    # Paramètres
    p = getPrime(256)
    g = 2
    
    # Autorité électorale
    x = secrets.randbelow(p - 2) + 1  # Clé privée
    h = pow(g, x, p)  # Clé publique
    
    print(f"  Clé publique de l'autorité : h = {str(h)[:30]}...")
    
    # Électeurs (3 candidats : 0, 1, 2)
    # Vote encodé : g^vote (vote = 0, 1, ou 2)
    votes = [0, 1, 2, 1, 0, 2, 1, 1, 0, 2]  # 10 électeurs
    
    print(f"\n  Votes en clair : {votes}")
    print(f"  Attendu : C0={votes.count(0)}, C1={votes.count(1)}, C2={votes.count(2)}")
    
    # Chiffrement des votes
    encrypted_votes = []
    for vote in votes:
        r = secrets.randbelow(p - 2) + 1
        c1 = pow(g, r, p)
        c2 = (pow(g, vote, p) * pow(h, r, p)) % p
        encrypted_votes.append((c1, c2))
        print(f"    Vote {vote} -> E(vote) = ({str(c1)[:15]}..., {str(c2)[:15]}...)")
    
    # Comptage homomorphe (multiplication des chiffrés)
    print(f"\n--- Comptage homomorphe ---")
    
    # Produit des c1 et c2
    prod_c1 = 1
    prod_c2 = 1
    for c1, c2 in encrypted_votes:
        prod_c1 = (prod_c1 * c1) % p
        prod_c2 = (prod_c2 * c2) % p
    
    print(f"  Produit des chiffrés :")
    print(f"    C1 = {str(prod_c1)[:30]}...")
    print(f"    C2 = {str(prod_c2)[:30]}...")
    
    # Déchiffrement du résultat
    s = pow(prod_c1, x, p)
    s_inv = inverse(s, p)
    result = (prod_c2 * s_inv) % p
    
    print(f"\n  Résultat déchiffré : g^(somme des votes) = {str(result)[:30]}...")
    
    # Trouver la somme (recherche exhaustive pour la démo)
    total_votes = sum(votes)
    expected = pow(g, total_votes, p)
    print(f"  Attendu (g^{total_votes}) : {str(expected)[:30]}...")
    print(f"  Match : {result == expected}")
    
    # Pour obtenir le décompte par candidat, on utiliserait
    # un encodage différent (bit par candidat)
    
    print(f"\n{'='*70}")
    print("AMÉLIORATIONS POUR UN VRAI SYSTÈME")
    print(f"{'='*70}")
    print("""
    1. Preuve à divulgation nulle de connaissance (ZKP) :
       - Prouver que le vote est valide (0, 1, ou 2)
       - Sans révéler le vote
    
    2. Mix-net :
       - Mélanger les votes chiffrés avant décompte
       - Briser le lien électeur/vote
    
    3. Chiffrement de Paillier (additif) :
       - E(v1 + v2) = E(v1) * E(v2) directement
       - Plus adapté au comptage de votes
    
    4. Bulletin board public :
       - Tous les votes chiffrés publiés
       - Vérification universelle du décompte
    """)


# ============================================
# Utilitaires réseau
# ============================================

def create_tls_context():
    """
    Crée un contexte TLS sécurisé
    """
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(certfile='server.crt', keyfile='server.key')
    return context


# ============================================
# MAIN
# ============================================

if __name__ == "__main__":
    print("=" * 70)
    print("TP6 - Application : Sécurisation des Communications")
    print("=" * 70)
    
    secure_socket_demo()
    bluetooth_security_demo()
    secure_chat_demo()
    homomorphic_voting_demo()
    
    print("\n" + "=" * 70)
    print("TP6 TERMINÉ")
    print("=" * 70)