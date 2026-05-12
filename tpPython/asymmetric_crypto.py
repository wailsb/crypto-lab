"""
TP3 - Cryptographie Asymétrique
Diffie-Hellman, RSA, ElGamal, ECC
"""

import os
import time
import hashlib
import secrets
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import DSS, pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.number import getPrime, inverse, GCD
from Crypto.Random import get_random_bytes
import sympy as sp


# ============================================
# EXERCICE 3.1 - Diffie-Hellman
# ============================================

def diffie_hellman_demo():
    """
    Échange de clés Diffie-Hellman + attaque MITM + contre-mesure ECDSA
    """
    print("=" * 70)
    print("EXERCICE 3.1 - Diffie-Hellman")
    print("=" * 70)
    
    # Paramètres publics
    p = getPrime(512)  # Premier de 512 bits (pédagogique, minimum demandé)
    g = 2  # Générateur
    
    print(f"\n--- Paramètres publics ---")
    print(f"  p (512 bits) : {str(p)[:30]}...")
    print(f"  g : {g}")
    
    # Alice
    a = secrets.randbelow(p - 2) + 1  # Clé privée d'Alice
    A = pow(g, a, p)  # Clé publique d'Alice
    
    # Bob
    b = secrets.randbelow(p - 2) + 1  # Clé privée de Bob
    B = pow(g, b, p)  # Clé publique de Bob
    
    print(f"\n--- Échange ---")
    print(f"  Alice : a (privé) = {str(a)[:20]}..., A = g^a mod p = {str(A)[:30]}...")
    print(f"  Bob   : b (privé) = {str(b)[:20]}..., B = g^b mod p = {str(B)[:30]}...")
    
    # Calcul du secret partagé
    K_alice = pow(B, a, p)
    K_bob = pow(A, b, p)
    
    print(f"\n--- Secret partagé ---")
    print(f"  K (Alice) = B^a mod p = {str(K_alice)[:30]}...")
    print(f"  K (Bob)   = A^b mod p = {str(K_bob)[:30]}...")
    print(f"  Match : {K_alice == K_bob}")
    
    # Dérivation d'une clé AES
    K_bytes = K_alice.to_bytes((K_alice.bit_length() + 7) // 8, 'big')
    K_aes = hashlib.sha256(K_bytes).digest()[:32]
    print(f"\n  Clé AES-256 dérivée : {K_aes.hex()[:20]}...")
    
    return p, g, a, A, b, B, K_alice


def diffie_hellman_mitm():
    """
    Attaque Man-in-the-Middle sur DH
    """
    print("\n" + "=" * 70)
    print("EXERCICE 3.1 - Attaque Man-in-the-Middle")
    print("=" * 70)
    
    p = getPrime(512)
    g = 2
    
    # Alice et Bob (légitimes)
    a = secrets.randbelow(p - 2) + 1
    A = pow(g, a, p)
    b = secrets.randbelow(p - 2) + 1
    B = pow(g, b, p)
    
    # Mallory (attaquant)
    m = secrets.randbelow(p - 2) + 1  # Clé privée de Mallory
    M = pow(g, m, p)  # Clé publique de Mallory (usurpée)
    
    print("""
    SCHÉMA DE L'ATTAQUE MITM :
    
    Alice                    Mallory (M)                    Bob
      |                         |                           |
      |-------- A = g^a --------|-> [intercepte]            |
      |                         |                           |
      |                         |<- M = g^m (envoyé à Bob)  |
      |                         |                           |
      |                         |    M = g^m (envoyé à Alice)
      |<- M = g^m (intercepté)|                           |
      |                         |                           |
      |                         |<-------- B = g^b --------|
      |                         |                           |
    
    Résultat :
    - Alice pense parler à Bob, partage K1 = M^a = g^(m*a) avec Mallory
    - Bob pense parler à Alice, partage K2 = M^b = g^(m*b) avec Mallory
    - Mallory déchiffre, relit, rechiffre tout le trafic !
    """)
    
    # Mallory intercepte A et envoie M à Bob
    # Mallory intercepte B et envoie M à Alice
    
    K_alice_mallory = pow(M, a, p)  # Alice calcule avec M (pense que c'est Bob)
    K_mallory_bob = pow(M, b, p)    # Bob calcule avec M (pense que c'est Alice)
    
    # Mallory peut calculer les deux secrets
    K_mallory_alice = pow(A, m, p)  # A^m = g^(a*m) = g^(m*a)
    K_mallory_bob2 = pow(B, m, p)   # B^m = g^(b*m) = g^(m*b)
    
    print(f"\n  Secrets établis :")
    print(f"    K(Alice-Mallory) = {str(K_alice_mallory)[:30]}...")
    print(f"    K(Mallory-Alice) = {str(K_mallory_alice)[:30]}...")
    print(f"    Match : {K_alice_mallory == K_mallory_alice}")
    print(f"\n    K(Mallory-Bob)   = {str(K_mallory_bob)[:30]}...")
    print(f"    K(Mallory-Bob2)  = {str(K_mallory_bob2)[:30]}...")
    print(f"    Match : {K_mallory_bob == K_mallory_bob2}")


def diffie_hellman_authentification():
    """
    Contre-mesure : signature ECDSA des clés publiques
    """
    print("\n" + "=" * 70)
    print("EXERCICE 3.1 - Contre-mesure : ECDSA")
    print("=" * 70)
    
    # Génération des clés ECDSA pour Alice et Bob
    key_alice = ECC.generate(curve='P-256')
    key_bob = ECC.generate(curve='P-256')
    
    print("  Clés ECDSA générées (P-256) pour Alice et Bob")
    
    # Paramètres DH
    p = getPrime(512)
    g = 2
    
    # Clés DH
    a = secrets.randbelow(p - 2) + 1
    A = pow(g, a, p)
    b = secrets.randbelow(p - 2) + 1
    B = pow(g, b, p)
    
    # Alice signe sa clé publique DH avec sa clé ECDSA privée
    h_A = SHA256.new(str(A).encode())
    signature_A = DSS.new(key_alice, 'fips-186-3').sign(h_A)
    
    # Bob signe sa clé publique DH avec sa clé ECDSA privée
    h_B = SHA256.new(str(B).encode())
    signature_B = DSS.new(key_bob, 'fips-186-3').sign(h_B)
    
    print(f"\n  Alice signe A = g^a mod p")
    print(f"  Signature A : {signature_A.hex()[:30]}...")
    print(f"\n  Bob signe B = g^b mod p")
    print(f"  Signature B : {signature_B.hex()[:30]}...")
    
    # Vérification par Bob (de la signature d'Alice)
    try:
        h_A_verify = SHA256.new(str(A).encode())
        DSS.new(key_alice.public_key(), 'fips-186-3').verify(h_A_verify, signature_A)
        print("\n  >>> Signature d'Alice VÉRIFIÉE ✓")
        print("  >>> Bob sait qu'il parle vraiment à Alice")
    except ValueError:
        print("  >>> Signature INVALIDE ✗")
    
    # Si Mallory essaie d'envoyer M au lieu de A
    m = secrets.randbelow(p - 2) + 1
    M = pow(g, m, p)
    
    # La signature ne correspond pas à M
    try:
        h_M = SHA256.new(str(M).encode())
        DSS.new(key_alice.public_key(), 'fips-186-3').verify(h_M, signature_A)
        print("  Mallory peut usurper")
    except ValueError:
        print("\n  >>> Si Mallory envoie M au lieu de A :")
        print("  >>> Signature INVALIDE ✗ - Attaque bloquée !")


# ============================================
# EXERCICE 3.2 - RSA
# ============================================

def rsa_demo():
    """
    RSA-512, 1024, 2048 + chiffrement hybride RSA+AES
    """
    print("\n" + "=" * 70)
    print("EXERCICE 3.2 - RSA")
    print("=" * 70)
    
    for key_size in [512, 1024, 2048]:
        print(f"\n--- RSA-{key_size} ---")
        
        # Génération
        start = time.time()
        key = RSA.generate(key_size)
        gen_time = time.time() - start
        
        print(f"  Temps de génération : {gen_time:.3f}s")
        print(f"  n = {str(key.n)[:30]}... ({key.n.bit_length()} bits)")
        print(f"  e = {key.e}")
        
        # Export des clés
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        
        print(f"  Clé privée : {len(private_key)} octets")
        print(f"  Clé publique : {len(public_key)} octets")
        
        # Chiffrement / Déchiffrement
        message = b"A" * 32  # 32 octets
        
        cipher = PKCS1_OAEP.new(key.publickey())
        ciphertext = cipher.encrypt(message)
        
        decipher = PKCS1_OAEP.new(key)
        decrypted = decipher.decrypt(ciphertext)
        
        print(f"  Message (32 octets) : {message[:10]}...")
        print(f"  Chiffré ({len(ciphertext)} octets) : {ciphertext[:20].hex()}...")
        print(f"  Déchiffré : {decrypted[:10]}...")
        print(f"  Match : {message == decrypted}")


def rsa_hybrid_encryption():
    """
    Chiffrement hybride RSA+AES pour fichier de 1 Mo
    """
    print("\n" + "=" * 70)
    print("EXERCICE 3.2 - Chiffrement hybride RSA+AES")
    print("=" * 70)
    
    # Générer clé RSA-2048
    rsa_key = RSA.generate(2048)
    
    # Générer clé AES-256 aléatoire
    aes_key = get_random_bytes(32)
    print(f"  Clé AES-256 : {aes_key.hex()[:20]}...")
    
    # Chiffrer la clé AES avec RSA
    cipher_rsa = PKCS1_OAEP.new(rsa_key.publickey())
    enc_aes_key = cipher_rsa.encrypt(aes_key)
    print(f"  Clé AES chiffrée (RSA) : {len(enc_aes_key)} octets")
    
    # Chiffrer le fichier (1 Mo) avec AES
    file_data = get_random_bytes(1024 * 1024)
    
    # AES seul
    start = time.time()
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv=get_random_bytes(16))
    enc_file_aes = cipher_aes.encrypt(pad(file_data, AES.block_size))
    aes_time = time.time() - start
    
    # RSA seul (théorique - en pratique impossible pour 1 Mo)
    # On simule avec un petit bloc pour comparaison
    start = time.time()
    small_block = get_random_bytes(200)  # Max pour RSA-2048 avec OAEP
    enc_small = cipher_rsa.encrypt(small_block)
    rsa_time_per_block = time.time() - start
    
    # Estimation pour 1 Mo
    n_blocks = len(file_data) // 200
    rsa_estimated_time = rsa_time_per_block * n_blocks
    
    print(f"\n  --- Performances ---")
    print(f"  AES seul (1 Mo) : {aes_time:.3f}s  ({1/aes_time:.1f} Mo/s)")
    print(f"  RSA (estimation 1 Mo) : {rsa_estimated_time:.1f}s")
    print(f"  Ratio RSA/AES : {rsa_estimated_time/aes_time:.0f}x plus lent")
    
    print(f"\n  >>> Pourquoi hybride ? RSA est {rsa_estimated_time/aes_time:.0f}x")
    print(f"  >>> plus lent qu'AES. On chiffre la clé AES avec RSA,")
    print(f"  >>> et les données avec AES.")


def rsa_questions():
    """
    Questions sur RSA et padding OAEP
    """
    print(f"\n{'='*70}")
    print("QUESTION : RSA et OAEP")
    print(f"{'='*70}")
    print("""
    1. Pourquoi RSA ne peut pas chiffrer directement un message arbitraire ?
    
    - RSA est un chiffrement par bloc : taille max = taille de n
    - Avec padding OAEP, la taille max = |n| - 2|H| - 2
      (H = fonction de hachage, ex: SHA-256)
    - Pour RSA-2048 : max ≈ 190 octets
    - Un fichier de 1 Mo nécessiterait 5000+ opérations RSA, très lent
    
    2. Qu'apporte OAEP par rapport à RSA textbook ?
    
    RSA textbook (m^e mod n) est vulnérable :
    - Déterministe : même message = même chiffré
    - Malleable : E(M1)*E(M2) = E(M1*M2)
    - Attaque par padding oracle
    - Pas de protection contre les attaques à clair choisi
    
    OAEP (Optimal Asymmetric Encryption Padding) :
    - Ajoute du sel aléatoire → indéterministe
    - Intègre un masque avec une fonction de hachage
    - Preuve de sécurité dans le modèle de l'oracle aléatoire
    - CCPA-sûr (Chosen Ciphertext Attack)
    """)


# ============================================
# EXERCICE 3.3 - ElGamal
# ============================================

def elgamal_demo():
    """
    ElGamal : génération, chiffrement, malléabilité
    """
    print("\n" + "=" * 70)
    print("EXERCICE 3.3 - ElGamal")
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
    
    # Chiffrement de M = 12345
    M = 12345
    
    # Non-déterminisme : k aléatoire à chaque chiffrement
    def encrypt_elgamal(M):
        k = secrets.randbelow(p - 2) + 1
        c1 = pow(g, k, p)
        c2 = (M * pow(y, k, p)) % p
        return (c1, c2)
    
    # Deux chiffrements du même M
    C1 = encrypt_elgamal(M)
    C2 = encrypt_elgamal(M)
    
    print(f"\n  M = {M}")
    print(f"  Chiffrement 1 : C1=({str(C1[0])[:20]}..., {str(C1[1])[:20]}...)")
    print(f"  Chiffrement 2 : C2=({str(C2[0])[:20]}..., {str(C2[1])[:20]}...)")
    print(f"  Différents ? {C1 != C2}  (non-déterminisme ✓)")
    
    # Déchiffrement
    def decrypt_elgamal(C, x, p):
        c1, c2 = C
        s = pow(c1, x, p)
        s_inv = inverse(s, p)
        M = (c2 * s_inv) % p
        return M
    
    M_decrypted = decrypt_elgamal(C1, x, p)
    print(f"\n  D(E(M)) = {M_decrypted}")
    print(f"  Match : {M == M_decrypted}")
    
    # Malléabilité
    print(f"\n--- Malléabilité ---")
    print("  E(M1) * E(M2) = E(M1 * M2 mod p)")
    
    M1 = 42
    M2 = 10
    
    enc_M1 = encrypt_elgamal(M1)
    enc_M2 = encrypt_elgamal(M2)
    
    # Multiplication des chiffrés
    c1_prod = (enc_M1[0] * enc_M2[0]) % p
    c2_prod = (enc_M1[1] * enc_M2[1]) % p
    
    # Déchiffrement du produit
    M_prod = decrypt_elgamal((c1_prod, c2_prod), x, p)
    
    print(f"  M1 = {M1}, M2 = {M2}")
    print(f"  M1 * M2 mod p = {(M1 * M2) % p}")
    print(f"  D(E(M1)*E(M2)) = {M_prod}")
    print(f"  Match : {M_prod == (M1 * M2) % p}")
    
    # Forger E(2M) à partir de E(M)
    print(f"\n--- Forger E(2M) sans connaître M ---")
    enc_M = encrypt_elgamal(M)
    
    # E(2M) = (C1, 2*C2 mod p)
    forged_c1 = enc_M[0]
    forged_c2 = (2 * enc_M[1]) % p
    
    M_forged = decrypt_elgamal((forged_c1, forged_c2), x, p)
    print(f"  M = {M}")
    print(f"  2M mod p = {(2 * M) % p}")
    print(f"  D(forgé) = {M_forged}")
    print(f"  Match : {M_forged == (2 * M) % p}")
    
    # Comparaison tailles
    print(f"\n{'='*70}")
    print("COMPARAISON RSA vs ElGamal (2048 bits)")
    print(f"{'='*70}")
    print("""
    RSA-2048 :
      - Chiffré : 256 octets (taille de n)
      - Clé publique : ~270 octets
      - Déchiffrement : exponentiation modulaire (rapide avec CRT)
    
    ElGamal-2048 :
      - Chiffré : 512 octets (C1 + C2, chacun 256 octets)
      - Clé publique : ~270 octets (p, g, y)
      - Déchiffrement : 2 exponentiations modulaires
    
    Implications :
      - ElGamal produit des chiffrés 2x plus gros
      - Moins efficace pour le stockage
      - Avantages : malléabilité utile pour homomorphisme
    """)


# ============================================
# EXERCICE 3.4 - ECC (Supplémentaire)
# ============================================

def ecc_demo():
    """
    Courbes elliptiques : addition de points, ECDH, ECIES
    """
    print("\n" + "=" * 70)
    print("EXERCICE 3.4 - Cryptographie sur Courbes Elliptiques (ECC)")
    print("=" * 70)
    
    # Courbe pédagogique : y^2 = x^3 + 7 mod 97
    p = 97
    a, b = 0, 7
    
    print(f"--- Courbe pédagogique ---")
    print(f"  y^2 = x^3 + {a}x + {b} mod {p}")
    
    # Vérifier qu'un point est sur la courbe
    def is_on_curve(x, y):
        return (y * y) % p == (x**3 + a*x + b) % p
    
    # Point G = (3, 6) sur la courbe ?
    G = (3, 6)
    print(f"\n  Point G = {G}")
    print(f"  Sur la courbe ? {is_on_curve(*G)}")
    
    # Addition de points (simplifiée)
    def point_add(P, Q):
        if P is None:
            return Q
        if Q is None:
            return P
        x1, y1 = P
        x2, y2 = Q
        
        if x1 == x2 and y1 != y2:
            return None  # Point à l'infini
        
        if P == Q:
            # Tangente
            m = ((3 * x1**2 + a) * inverse(2 * y1, p)) % p
        else:
            # Corde
            m = ((y2 - y1) * inverse(x2 - x1, p)) % p
        
        x3 = (m**2 - x1 - x2) % p
        y3 = (m * (x1 - x3) - y1) % p
        return (x3, y3)
    
    # Multiplication scalaire
    def scalar_mult(k, P):
        result = None
        addend = P
        while k:
            if k & 1:
                result = point_add(result, addend)
            addend = point_add(addend, addend)
            k >>= 1
        return result
    
    # Vérifier 2G
    G2 = scalar_mult(2, G)
    print(f"\n  2G = {G2}")
    print(f"  Sur la courbe ? {is_on_curve(*G2) if G2 else 'infini'}")
    
    # Vérifier 3G = G + 2G
    G3 = point_add(G, G2)
    G3_bis = scalar_mult(3, G)
    print(f"  3G (G+2G) = {G3}")
    print(f"  3G (direct) = {G3_bis}")
    print(f"  Match : {G3 == G3_bis}")
    
    # ECDH sur P-256 avec pycryptodome
    print(f"\n--- ECDH sur P-256 (réel) ---")
    
    key_a = ECC.generate(curve='P-256')
    key_b = ECC.generate(curve='P-256')
    
    print("  Clés générées sur P-256")
    
    # Échange
    pub_a = key_a.public_key()
    pub_b = key_b.public_key()
    
    # Secret partagé
    shared_a = key_a.d * pub_b.pointQ
    shared_b = key_b.d * pub_a.pointQ
    
    print(f"\n  Secret A : {str(shared_a.x)[:30]}...")
    print(f"  Secret B : {str(shared_b.x)[:30]}...")
    print(f"  Match : {shared_a.x == shared_b.x}")
    
    # Dérivation AES-256 via SHA256
    shared_bytes = int(shared_a.x).to_bytes(32, 'big')
    aes_key = hashlib.sha256(shared_bytes).digest()
    print(f"\n  Clé AES-256 dérivée : {aes_key.hex()[:20]}...")
    
    # ECIES simplifié
    print(f"\n--- ECIES simplifié ---")
    message = b"Message secret pour Bob"
    
    # Alice chiffre pour Bob
    ephemeral = ECC.generate(curve='P-256')
    shared = ephemeral.d * pub_b.pointQ
    shared_bytes = int(shared.x).to_bytes(32, 'big')
    
    # Dérivation de clé
    enc_key = hashlib.sha256(b'enc' + shared_bytes).digest()[:16]
    mac_key = hashlib.sha256(b'mac' + shared_bytes).digest()[:16]
    
    # Chiffrement AES
    iv = get_random_bytes(16)
    cipher = AES.new(enc_key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pad(message, AES.block_size))
    
    # MAC
    mac = hashlib.sha256(mac_key + ciphertext).digest()[:16]
    
    print(f"  Message : {message}")
    print(f"  Chiffré : {ciphertext.hex()[:30]}...")
    print(f"  R = clé publique éphémère : envoyée à Bob")
    
    # Bob déchiffre
    shared_bob = key_b.d * ephemeral.public_key().pointQ
    shared_bytes_bob = int(shared_bob.x).to_bytes(32, 'big')
    
    enc_key_bob = hashlib.sha256(b'enc' + shared_bytes_bob).digest()[:16]
    mac_key_bob = hashlib.sha256(b'mac' + shared_bytes_bob).digest()[:16]
    
    # Vérifier MAC
    mac_bob = hashlib.sha256(mac_key_bob + ciphertext).digest()[:16]
    print(f"  MAC valide ? {mac == mac_bob}")
    
    # Déchiffrement
    decipher = AES.new(enc_key_bob, AES.MODE_CBC, iv=iv)
    decrypted = unpad(decipher.decrypt(ciphertext), AES.block_size)
    print(f"  Déchiffré : {decrypted}")
    print(f"  Match : {message == decrypted}")
    
    print(f"\n{'='*70}")
    print("SÉCURITÉ ECC : ECC-256 ≈ RSA-3072 (NIST SP 800-57)")
    print(f"{'='*70}")
    print("""
    Avantages d'ECC :
    - Clés beaucoup plus courtes (256 bits vs 3072 bits)
    - Calculs plus rapides
    - Moins de consommation énergétique (mobile/IoT)
    - Même niveau de sécurité
    """)


# ============================================
# MAIN
# ============================================

if __name__ == "__main__":
    print("=" * 70)
    print("TP3 - Cryptographie Asymétrique")
    print("=" * 70)
    
    diffie_hellman_demo()
    diffie_hellman_mitm()
    diffie_hellman_authentification()
    rsa_demo()
    rsa_hybrid_encryption()
    rsa_questions()
    elgamal_demo()
    ecc_demo()
    
    print("\n" + "=" * 70)
    print("TP3 TERMINÉ")
    print("=" * 70)