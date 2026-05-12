"""
TP1 - Exercice 1.4 : One-Time Pad (Vernam)
Génération de clé, chiffrement XOR, vulnérabilité de réutilisation
"""

import os
import secrets
from collections import Counter


def generer_cle_otp(longueur: int) -> bytes:
    """Génère une clé aléatoire de 'longueur' octets."""
    return secrets.token_bytes(longueur)


def chiffrer_otp(message: bytes, cle: bytes) -> bytes:
    """Chiffre par XOR octet à octet."""
    if len(message) != len(cle):
        raise ValueError("La clé doit avoir la même longueur que le message")
    return bytes(m ^ k for m, k in zip(message, cle))


def dechiffrer_otp(cryptogramme: bytes, cle: bytes) -> bytes:
    """Le déchiffrement OTP est identique au chiffrement (XOR)."""
    return chiffrer_otp(cryptogramme, cle)


def crib_dragging(c1_xor_c2: bytes, cribs: list) -> dict:
    """
    Attaque par crib dragging : teste des mots probables (cribs)
    sur C1 XOR C2 pour retrouver des fragments de M1 ou M2.
    """
    print("=" * 60)
    print("CRIB DRAGGING ATTACK")
    print("=" * 60)
    
    resultats = {}
    
    for crib in cribs:
        crib_bytes = crib.encode('utf-8', errors='ignore')
        
        for pos in range(len(c1_xor_c2) - len(crib_bytes) + 1):
            # XOR du crib avec C1 XOR C2 à la position pos
            extrait = bytes(c1_xor_c2[pos + i] ^ crib_bytes[i] 
                          for i in range(len(crib_bytes)))
            
            # Vérifier si le résultat est lisible (ASCII printable)
            try:
                texte = extrait.decode('ascii')
                if all(32 <= ord(c) <= 126 for c in texte):
                    print(f"  Position {pos}, crib='{crib}' -> '{texte}'")
                    resultats[pos] = (crib, texte)
            except:
                pass
    
    return resultats


# ============== DÉMONSTRATION ==============

if __name__ == "__main__":
    print("=" * 60)
    print("DÉMONSTRATION - ONE-TIME PAD")
    print("=" * 60)
    
    # Messages
    M1 = b"Hello World! This is a secret message."
    M2 = b"Bonjour monde! Ceci est un message secret."
    
    print(f"M1 : {M1}")
    print(f"M2 : {M2}")
    
    # Générer une clé aléatoire
    longueur = max(len(M1), len(M2))
    K = generer_cle_otp(longueur)
    print(f"\nClé générée ({len(K)} octets) : {K.hex()[:20]}...")
    
    # Chiffrement
    C1 = chiffrer_otp(M1, K[:len(M1)])
    C2 = chiffrer_otp(M2, K[:len(M2)])
    
    print(f"\nC1 : {C1.hex()[:30]}...")
    print(f"C2 : {C2.hex()[:30]}...")
    
    # Déchiffrement
    M1_dechiffre = dechiffrer_otp(C1, K[:len(M1)])
    M2_dechiffre = dechiffrer_otp(C2, K[:len(M2)])
    
    print(f"\nM1 déchiffré : {M1_dechiffre}")
    print(f"M2 déchiffré : {M2_dechiffre}")
    print(f"Restitution exacte : {M1 == M1_dechiffre and M2 == M2_dechiffre}")
    
    # ============== VULNÉRABILITÉ DE RÉUTILISATION ==============
    print("\n" + "=" * 60)
    print("VULNÉRABILITÉ : RÉUTILISATION DE CLÉ")
    print("=" * 60)
    
    # Même clé K utilisée pour M1 et M2
    K_reutilisee = generer_cle_otp(longueur)
    
    C1_reuse = chiffrer_otp(M1, K_reutilisee[:len(M1)])
    C2_reuse = chiffrer_otp(M2, K_reutilisee[:len(M2)])
    
    # C1 XOR C2 = M1 XOR M2 (la clé s'annule !)
    # On prend la longueur minimale
    min_len = min(len(C1_reuse), len(C2_reuse))
    C1_xor_C2 = bytes(c1 ^ c2 for c1, c2 in zip(C1_reuse[:min_len], C2_reuse[:min_len]))
    
    print(f"\nC1 (avec K réutilisée) : {C1_reuse.hex()[:30]}...")
    print(f"C2 (avec K réutilisée) : {C2_reuse.hex()[:30]}...")
    print(f"\nC1 XOR C2 = M1 XOR M2 : {C1_xor_C2.hex()[:30]}...")
    
    # Analyse statistique
    print("\n--- Analyse statistique sur M1 XOR M2 ---")
    
    # Crib dragging avec des mots probables
    cribs = [
        "Hello", "World", "secret", "message", "the", "and",
        "Bonjour", "monde", "Ceci", "est", "un", "message",
        "This", "is", "a", "secret", "message"
    ]
    
    crib_dragging(C1_xor_C2, cribs)
    
    # ============== QUESTION ==============
    print(f"\n{'='*60}")
    print("QUESTION : Pourquoi OTP est théoriquement parfait mais pratiquement inutilisable")
    print(f"{'='*60}")
    print("""
    L'OTP est théoriquement parfait (Shannon, 1949) car :
    - La clé doit être aussi longue que le message
    - La clé doit être vraiment aléatoire
    - La clé ne doit JAMAIS être réutilisée
    - La clé doit être tenue secrète
    
    Obstacles concrets :
    1. Distribution de clé : Comment transmettre une clé aussi longue
       que le message de manière sécurisée ? Le problème revient à
       celui de transmettre le message lui-même.
    2. Génération d'aléa vrai : Les PRNG ne sont pas suffisants,
       il faut de l'aléa physique (bruit thermique, etc.).
    3. Synchronisation : Émetteur et récepteur doivent partager
       exactement la même clé au même moment.
    4. Stockage : Stocker des téraoctets de clés est impraticable.
    5. Réutilisation accidentelle : Une seule réutilisation compromet
       tous les messages (comme démontré ci-dessus).
    
    Solutions pratiques : 
    - Chiffrement par flux (RC4, ChaCha20) avec clé courte + nonce
    - Échange de clés quantique (QKD) pour la distribution
    """)