#!/usr/bin/env python3
"""
TP1 - Cryptographie Appliquée : Chiffrement Classique
César, Vigenère, Hill, OTP (Vernam)
"""

import string
import numpy as np
import secrets
from collections import Counter, defaultdict
from sympy import Matrix, mod_inverse

ALPHABET = string.ascii_lowercase
MOD = 26
IC_FRANCAIS = 0.074

# ============================================
# PARTIE 1 : CÉSAR
# ============================================

def chiffrer_cesar(texte, k):
    texte = texte.lower()
    return "".join(ALPHABET[(ALPHABET.index(c) + k) % 26] 
                   if c in ALPHABET else "" for c in texte)

def dechiffrer_cesar(texte, k):
    return chiffrer_cesar(texte, -k)

# ============================================
# PARTIE 2 : VIGENÈRE
# ============================================

def chiffrer_vigenere(texte, cle):
    texte = [c for c in texte.lower() if c in ALPHABET]
    cle = cle.lower()
    return "".join(ALPHABET[(ALPHABET.index(texte[i]) + 
                             ALPHABET.index(cle[i % len(cle)])) % 26] 
                   for i in range(len(texte)))

def dechiffrer_vigenere(texte, cle):
    cle = cle.lower()
    return "".join(ALPHABET[(ALPHABET.index(texte[i]) - 
                             ALPHABET.index(cle[i % len(cle)])) % 26] 
                   for i in range(len(texte)))

# ============================================
# PARTIE 3 : HILL
# ============================================

def chiffrer_hill(texte, cle):
    taille = cle.shape[0]
    texte = [c for c in texte.lower() if c in ALPHABET]
    while len(texte) % taille != 0:
        texte.append('x')
    resultat = []
    for i in range(0, len(texte), taille):
        v = np.array([ALPHABET.index(c) for c in texte[i:i+taille]])
        chiffre = (cle @ v) % MOD
        resultat.extend(chiffre)
    return "".join(ALPHABET[int(x)] for x in resultat)

def inverse_modulaire_matrice(matrice, mod=26):
    M = Matrix(matrice)
    return np.array(M.inv_mod(mod), dtype=int)

# ============================================
# PARTIE 4 : OTP
# ============================================

def chiffrer_otp(message, cle):
    return bytes(m ^ k for m, k in zip(message, cle))

# ============================================
# MAIN
# ============================================

if __name__ == "__main__":
    print("=" * 60)
    print("TP1 - Chiffrement Classique - Tests rapides")
    print("=" * 60)
    
    # César
    print("\n--- César ---")
    msg = "hello"
    k = 3
    c = chiffrer_cesar(msg, k)
    print(f"{msg} -> {c} (k={k}) -> {dechiffrer_cesar(c, k)}")
    
    # Vigenère
    print("\n--- Vigenère ---")
    msg = "attackatdawn"
    cle = "lemon"
    c = chiffrer_vigenere(msg, cle)
    print(f"{msg} -> {c} (clé={cle}) -> {dechiffrer_vigenere(c, cle)}")
    
    # Hill
    print("\n--- Hill ---")
    K = np.array([[3, 3], [2, 5]])
    msg = "help"
    c = chiffrer_hill(msg, K)
    print(f"{msg} -> {c}")
    
    # OTP
    print("\n--- OTP ---")
    msg = b"SECRET"
    cle = secrets.token_bytes(len(msg))
    c = chiffrer_otp(msg, cle)
    d = chiffrer_otp(c, cle)
    print(f"{msg} -> {c.hex()} -> {d}")