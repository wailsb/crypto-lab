"""
TP5 - Signatures Numériques
RSA-PSS, ElGamal, DSA, ECDSA
"""

import hashlib
import time
from Crypto.PublicKey import RSA, DSA, ECC # type: ignore
from Crypto.Signature import pss, DSS, pkcs1_15 # type: ignore
from Crypto.Hash import SHA256 # type: ignore
from Crypto.Random import get_random_bytes # type: ignore
from Crypto.Util.number import getPrime, inverse, GCD # type: ignore
import secrets


# ============================================
# EXERCICE 5.1 - Signature RSA (PKCS#1 v1.5 et PSS)
# ============================================

def rsa_signature_demo():
    """
    RSA : signatures PKCS#1 v1.5 et PSS
    """
    print("=" * 70)
    print("EXERCICE 5.1 - Signature RSA")
    print("=" * 70)
    
    # Génération clé RSA-2048
    key = RSA.generate(2048)
    message = "Document important à signer"
    
    print(f"  Message : {message}")
    
    # --- PKCS#1 v1.5 ---
    print(f"\n--- PKCS#1 v1.5 ---")
    h = SHA256.new(message)
    signature_v15 = pkcs1_15.new(key).sign(h)
    
    print(f"  Signature : {signature_v15.hex()[:40]}...")
    print(f"  Taille : {len(signature_v15)} octets")
    
    # Vérification
    try:
        pkcs1_15.new(key.publickey()).verify(h, signature_v15)
        print("  Vérification : VALIDE ✓")
    except (ValueError, TypeError):
        print("  Vérification : INVALIDE ✗")
    
    # --- PSS (Probabilistic Signature Scheme) ---
    print(f"\n--- RSA-PSS ---")
    h = SHA256.new(message)
    signature_pss = pss.new(key).sign(h)
    
    print(f"  Signature : {signature_pss.hex()[:40]}...")
    print(f"  Taille : {len(signature_pss)} octets")
    
    # Vérification
    try:
        pss.new(key.publickey()).verify(h, signature_pss)
        print("  Vérification : VALIDE ✓")
    except (ValueError, TypeError):
        print("  Vérification : INVALIDE ✗")
    
    # Comparaison
    print(f"\n--- Comparaison ---")
    print("  PKCS#1 v1.5 :")
    print("    - Déterministe (même message = même signature)")
    print("    - Vulnérable aux attaques par padding oracle (Bleichenbacher)")
    print("  PSS :")
    print("    - Probabiliste (sel aléatoire)")
    print("    - Preuve de sécurité dans le modèle oracle aléatoire")
    print("    - RECOMMANDÉ (RFC 8017)")


# ============================================
# EXERCICE 5.2 - Signature ElGamal
# ============================================

def elgamal_signature_demo():
    """
    Signature ElGamal (implémentation pédagogique)
    """
    print("\n" + "=" * 70)
    print("EXERCICE 5.2 - Signature ElGamal")
    print("=" * 70)
    
    # Paramètres
    p = getPrime(512)
    g = 2
    
    # Clés
    x = secrets.randbelow(p - 2) + 1  # Clé privée
    y = pow(g, x, p)  # Clé publique
    
    print(f"  p = {str(p)[:30]}...")
    print(f"  g = {g}")
    print(f"  x (privé) = {str(x)[:20]}...")
    print(f"  y = g^x = {str(y)[:30]}...")
    
    # Message à signer
    message = b"Message a signer"
    h = int(hashlib.sha256(message).hexdigest(), 16) % p
    
    print(f"\n  Message : {message}")
    print(f"  H(M) mod p = {str(h)[:20]}...")
    
    # Signature : (r, s)
    k = secrets.randbelow(p - 2) + 1
    while GCD(k, p - 1) != 1:
        k = secrets.randbelow(p - 2) + 1
    
    r = pow(g, k, p)
    s = ((h - x * r) * inverse(k, p - 1)) % (p - 1)
    
    signature = (r, s)
    print(f"\n  Signature :")
    print(f"    r = {str(r)[:20]}...")
    print(f"    s = {str(s)[:20]}...")
    
    # Vérification
    # v1 = g^h mod p
    # v2 = y^r * r^s mod p
    v1 = pow(g, h, p)
    v2 = (pow(y, r, p) * pow(r, s, p)) % p
    
    print(f"\n  Vérification :")
    print(f"    g^H(M) mod p = {str(v1)[:20]}...")
    print(f"    y^r * r^s mod p = {str(v2)[:20]}...")
    print(f"    Match : {v1 == v2}")
    
    # Attaque si k réutilisé
    print(f"\n--- ATTENTION : Si k est réutilisé ---")
    print("  Deux signatures avec même k permettent de retrouver x")
    print("  (PlayStation 3 hack 2010 - faille similaire)")


# ============================================
# EXERCICE 5.3 - DSA et ECDSA
# ============================================

def dsa_ecdsa_demo():
    """
    DSA et ECDSA : génération, signature, vérification
    """
    print("\n" + "=" * 70)
    print("EXERCICE 5.3 - DSA et ECDSA")
    print("=" * 70)
    
    message = b"Document a signer avec DSA/ECDSA"
    h = SHA256.new(message)
    
    # --- DSA ---
    print(f"\n--- DSA ---")
    key_dsa = DSA.generate(2048)
    
    signature_dsa = DSS.new(key_dsa, 'fips-186-3').sign(h)
    print(f"  Signature DSA : {signature_dsa.hex()[:40]}...")
    print(f"  Taille : {len(signature_dsa)} octets")
    
    # Vérification
    try:
        DSS.new(key_dsa.public_key(), 'fips-186-3').verify(h, signature_dsa)
        print("  Vérification : VALIDE ✓")
    except ValueError:
        print("  Vérification : INVALIDE ✗")
    
    # --- ECDSA ---
    print(f"\n--- ECDSA (P-256) ---")
    key_ecdsa = ECC.generate(curve='P-256')
    
    signature_ecdsa = DSS.new(key_ecdsa, 'fips-186-3').sign(h)
    print(f"  Signature ECDSA : {signature_ecdsa.hex()[:40]}...")
    print(f"  Taille : {len(signature_ecdsa)} octets")
    
    # Vérification
    try:
        DSS.new(key_ecdsa.public_key(), 'fips-186-3').verify(h, signature_ecdsa)
        print("  Vérification : VALIDE ✓")
    except ValueError:
        print("  Vérification : INVALIDE ✗")
    
    # Comparaison tailles
    print(f"\n--- Comparaison ---")
    print(f"  DSA-2048 signature : {len(signature_dsa)} octets")
    print(f"  ECDSA-P256 signature : {len(signature_ecdsa)} octets")
    print(f"  >>> ECDSA 2x plus compact !")
    
    # Attaque si nonce réutilisé
    print(f"\n--- Vulnérabilité : nonce réutilisé ---")
    print("  Si le même k est utilisé pour deux messages différents :")
    print("  On peut résoudre un système d'équations pour trouver la clé privée")
    print("  (Faille Sony PS3 2010 - k constant dans le firmware)")


# ============================================
# Attaques et contre-mesures
# ============================================

def signature_attacks():
    """
    Attaques sur les signatures et contre-mesures
    """
    print("\n" + "=" * 70)
    print("ATTAQUES ET CONTRE-MESURES")
    print("=" * 70)
    
    print("""
    1. ATTAQUE PAR FORGE (RSA textbook) :
       - Sans padding, on peut forger des signatures
       - Contre-mesure : OAEP/PSS avec hachage
    
    2. ATTAQUE PAR RÉUTILISATION DE k (DSA/ECDSA) :
       - Deux signatures avec même k → clé privée exposée
       - Contre-mesure : générer k avec HMAC-DRBG ou RFC 6979
    
    3. ATTAQUE PAR FAUTE (Fault attack) :
       - Injection de faute pendant la signature
       - Contre-mesure : vérification après signature
    
    4. ATTAQUE PAR CANAL AUXILIAIRE :
       - Analyse de consommation électrique/timing
       - Contre-mesure : implémentations constant-time
    """)


# ============================================
# MAIN
# ============================================

if __name__ == "__main__":
    print("=" * 70)
    print("TP5 - Signatures Numériques")
    print("=" * 70)
    
    rsa_signature_demo()
    elgamal_signature_demo()
    dsa_ecdsa_demo()
    signature_attacks()
    
    print("\n" + "=" * 70)
    print("TP5 TERMINÉ")
    print("=" * 70)