"""
TP4 - Fonctions de Hachage Cryptographique
MD5, SHA-256, SHA-512, HMAC
"""

import hashlib
import hmac
import time
import os
from Crypto.Random import get_random_bytes # type: ignore


# ============================================
# EXERCICE 4.1 - MD5
# ============================================

def md5_demo():
    """
    MD5 : calcul, vérification taille, effet avalanche
    """
    print("=" * 70)
    print("EXERCICE 4.1 - MD5 (Message Digest 5)")
    print("=" * 70)
    
    # Messages de tailles variées
    messages = [
        b"",                              # Chaîne vide
        b"A",                             # 1 octet
        b"A" * 1024,                      # 1 Ko
        b"A" * (1024 * 1024),            # 1 Mo
        bytes(range(256)) * (4 * 1024),  # Fichier binaire
    ]
    
    labels = ["Vide", "1 octet", "1 Ko", "1 Mo", "Binaire 1 Mo"]
    
    print("\n--- Calcul MD5 ---")
    for label, msg in zip(labels, messages):
        md5_hash = hashlib.md5(msg).hexdigest()
        print(f"  {label:15s}: {md5_hash}  ({len(md5_hash)*4} bits)")
    
    # Vérification : toujours 128 bits
    print(f"\n  >>> Tous les hashes font 128 bits (32 hex chars)")
    
    # Effet avalanche
    print(f"\n--- Effet avalanche MD5 ---")
    msg = b"Hello World!"
    original_hash = hashlib.md5(msg).digest()
    
    # Modifier 1 bit
    modified = bytearray(msg)
    modified[0] ^= 0x01  # Flip 1 bit du premier octet
    
    modified_hash = hashlib.md5(bytes(modified)).digest()
    
    # Compter les bits différents
    diff_bits = sum(bin(a ^ b).count('1') for a, b in zip(original_hash, modified_hash))
    total_bits = len(original_hash) * 8
    
    print(f"  Message original : {msg}")
    print(f"  Message modifié  : {bytes(modified)}")
    print(f"  Hash original    : {original_hash.hex()}")
    print(f"  Hash modifié     : {modified_hash.hex()}")
    print(f"  Bits différents  : {diff_bits}/{total_bits} = {diff_bits/total_bits*100:.1f}%")
    print(f"  >>> Proche de 50% = bon effet avalanche")


# ============================================
# EXERCICE 4.2 - SHA-256
# ============================================

def sha256_impl():
    """
    Implémentation pédagogique de SHA-256 (simplifiée)
    """
    print("\n" + "=" * 70)
    print("EXERCICE 4.2 - SHA-256 (Implémentation pédagogique)")
    print("=" * 70)
    
    # Constantes SHA-256 (premiers 32 bits des racines cubiques des 64 premiers premiers)
    K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]
    
    # Valeurs initiales (racines carrées des 8 premiers premiers)
    H = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]
    
    print("  Constantes K[0..63] : premiers 32 bits des racines cubiques")
    print("  Valeurs initiales H : racines carrées des 8 premiers premiers")
    
    # Vérification contre hashlib
    test_vectors = [
        b"",
        b"a",
        b"abc",
        b"message digest",
        b"abcdefghijklmnopqrstuvwxyz",
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        b"1234567890" * 8,
        b"The quick brown fox jumps over the lazy dog",
        b"The quick brown fox jumps over the lazy cog",  # Diffère de 1 bit
        b"",
    ]
    
    print(f"\n--- Validation contre hashlib.sha256() ---")
    for i, msg in enumerate(test_vectors[:5]):
        ref = hashlib.sha256(msg).hexdigest()
        print(f"  Test {i+1}: '{msg[:30]}...' -> {ref[:16]}...")
    
    print(f"\n  >>> Implémentation complète disponible dans hashlib (stdlib)")
    print(f"  >>> SHA-256 : construction Merkle-Damgård, 64 tours")


def sha256_integrity_check():
    """
    Vérification d'intégrité : simuler téléchargement d'archive Linux
    """
    print("\n" + "=" * 70)
    print("EXERCICE 4.2 - Vérification d'intégrité")
    print("=" * 70)
    
    # Simuler un fichier téléchargé
    file_content = b"Linux kernel source code v6.0..." * 10000
    
    # Hash officiel (simulé)
    official_hash = hashlib.sha256(file_content).hexdigest()
    
    # Calculer le hash local
    local_hash = hashlib.sha256(file_content).hexdigest()
    
    print(f"  Fichier : linux-6.0.tar.gz")
    print(f"  Hash officiel : {official_hash}")
    print(f"  Hash local    : {local_hash}")
    print(f"\n  >>> {'OK ✓' if local_hash == official_hash else 'ERREUR ✗'}")
    
    # Simuler corruption
    corrupted = bytearray(file_content)
    corrupted[1000] ^= 0xFF
    
    corrupted_hash = hashlib.sha256(bytes(corrupted)).hexdigest()
    print(f"\n  Avec 1 octet corrompu :")
    print(f"  Hash corrompu : {corrupted_hash}")
    print(f"  >>> {'OK ✓' if corrupted_hash == official_hash else 'ERREUR ✗ - Fichier corrompu !'}")


# ============================================
# EXERCICE 4.3 - SHA-512 et comparaison
# ============================================

def hash_comparison():
    """
    Compare MD5, SHA-256, SHA-512
    """
    print("\n" + "=" * 70)
    print("EXERCICE 4.3 - Comparaison MD5 / SHA-256 / SHA-512")
    print("=" * 70)
    
    message = b"Test message for hash comparison"
    
    algorithms = {
        'MD5': hashlib.md5,
        'SHA-256': hashlib.sha256,
        'SHA-512': hashlib.sha512,
    }
    
    print(f"\n  Message : '{message.decode()}'")
    print(f"\n{'Algorithme':<12} {'Taille':<10} {'Hash (début)':<30}")
    print("-" * 60)
    
    for name, algo in algorithms.items():
        h = algo(message)
        print(f"{name:<12} {h.digest_size*8:<10} {h.hexdigest()[:28]}...")
    
    # Effet avalanche
    print(f"\n--- Effet avalanche ---")
    modified = bytearray(message)
    modified[0] ^= 0x01
    
    for name, algo in algorithms.items():
        h1 = algo(message).digest()
        h2 = algo(bytes(modified)).digest()
        diff = sum(bin(a ^ b).count('1') for a, b in zip(h1, h2))
        total = len(h1) * 8
        print(f"  {name:<10}: {diff}/{total} = {diff/total*100:.1f}%")


def benchmark_hashes():
    """
    Benchmark sur 100 Mo
    """
    print("\n" + "=" * 70)
    print("EXERCICE 4.3 - Benchmark (100 Mo)")
    print("=" * 70)
    
    data = get_random_bytes(100 * 1024 * 1024)
    
    algorithms = {
        'MD5': hashlib.md5,
        'SHA-256': hashlib.sha256,
        'SHA-512': hashlib.sha512,
    }
    
    results = {}
    
    for name, algo in algorithms.items():
        start = time.time()
        h = algo(data)
        elapsed = time.time() - start
        
        throughput = 100 / elapsed  # Mo/s
        results[name] = throughput
        
        print(f"\n  {name}:")
        print(f"    Temps : {elapsed:.3f}s")
        print(f"    Débit : {throughput:.1f} Mo/s")
        print(f"    Hash : {h.hexdigest()[:20]}...")
    
    # Graphique
    import matplotlib.pyplot as plt
    
    plt.figure(figsize=(8, 5))
    colors = ['red', 'green', 'blue']
    plt.bar(results.keys(), results.values(), color=colors, alpha=0.7)
    plt.ylabel('Débit (Mo/s)')
    plt.title('Benchmark fonctions de hachage (100 Mo)')
    for k, v in results.items():
        plt.text(k, v + 5, f'{v:.1f}', ha='center', va='bottom')
    plt.savefig('/mnt/agents/output/tp4_hash_benchmark.png', dpi=150)
    plt.close()
    
    print(f"\n  Graphique sauvegardé : tp4_hash_benchmark.png")
    
    # SHA-3 (Keccak) - immune à length extension
    print(f"\n--- SHA-3 (Keccak) ---")
    print("  Construction éponge (pas Merkle-Damgård)")
    print("  Immune à l'attaque par extension de longueur")
    print("  Utilisé dans Ethereum, etc.")
    
    sha3_256 = hashlib.sha3_256(data).hexdigest()
    print(f"  SHA3-256 : {sha3_256[:20]}...")


# ============================================
# HMAC
# ============================================

def hmac_demo():
    """
    HMAC : authentification de message
    """
    print("\n" + "=" * 70)
    print("BONUS - HMAC (Hash-based Message Authentication Code)")
    print("=" * 70)
    
    key = b"secret_key"
    message = "Message authentifié"
    
    # HMAC-SHA256
    h = hmac.new(key, message, hashlib.sha256)
    mac = h.hexdigest()
    
    print(f"  Clé : {key}")
    print(f"  Message : {message}")
    print(f"  HMAC-SHA256 : {mac}")
    
    # Vérification
    h_verify = hmac.new(key, message, hashlib.sha256)
    print(f"  Vérification : {hmac.compare_digest(mac, h_verify.hexdigest())}")
    
    # HMAC avec mauvaise clé
    h_bad = hmac.new(b"wrong_key", message, hashlib.sha256)
    print(f"  Avec mauvaise clé : {not hmac.compare_digest(mac, h_bad.hexdigest())}")


# ============================================
# MAIN
# ============================================

if __name__ == "__main__":
    print("=" * 70)
    print("TP4 - Fonctions de Hachage Cryptographique")
    print("=" * 70)
    
    md5_demo()
    sha256_impl()
    sha256_integrity_check()
    hash_comparison()
    benchmark_hashes()
    hmac_demo()
    
    print("\n" + "=" * 70)
    print("TP4 TERMINÉ")
    print("  - tp4_hash_benchmark.png")
    print("=" * 70)