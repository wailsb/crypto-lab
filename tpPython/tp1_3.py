"""
TP1 - Exercice 1.3 : Chiffre de Hill
Chiffrement par blocs, inverse modulaire, attaque à clair connu
"""

import string
import numpy as np
from sympy import Matrix, mod_inverse

ALPHABET = string.ascii_lowercase
MOD = 26


def lettre_vers_nombre(c: str) -> int:
    return ALPHABET.index(c.lower())


def nombre_vers_lettre(n: int) -> str:
    return ALPHABET[n % MOD]


def matrice_vers_texte(matrice: np.ndarray) -> str:
    """Convertit une matrice de nombres en texte."""
    return "".join(nombre_vers_lettre(int(x)) for x in matrice.flatten())


def texte_vers_vecteurs(texte: str, taille_bloc: int) -> list:
    """Convertit un texte en liste de vecteurs numériques."""
    texte = [c for c in texte.lower() if c in ALPHABET]
    
    # Padding si nécessaire
    while len(texte) % taille_bloc != 0:
        texte.append('x')
    
    vecteurs = []
    for i in range(0, len(texte), taille_bloc):
        bloc = texte[i:i+taille_bloc]
        vecteurs.append(np.array([lettre_vers_nombre(c) for c in bloc]))
    
    return vecteurs


def inverse_modulaire_matrice(matrice: np.ndarray, mod: int = 26) -> np.ndarray:
    """
    Calcule l'inverse modulaire d'une matrice.
    Formule : K^(-1) = det(K)^(-1) × adj(K) mod 26
    """
    # Utiliser sympy pour le calcul exact
    M = Matrix(matrice)
    
    # Vérifier que le déterminant est inversible mod 26
    det = int(M.det())
    try:
        det_inv = mod_inverse(det % mod, mod)
    except ValueError:
        raise ValueError(f"Le déterminant {det} n'est pas inversible mod {mod}")
    
    # Calculer l'inverse
    M_inv = M.inv_mod(mod)
    return np.array(M_inv, dtype=int)


def chiffrer_hill(texte: str, cle: np.ndarray) -> str:
    """Chiffre un texte avec Hill."""
    taille = cle.shape[0]
    vecteurs = texte_vers_vecteurs(texte, taille)
    
    resultat = []
    for v in vecteurs:
        chiffre = (cle @ v) % MOD
        resultat.extend(chiffre)
    
    return "".join(nombre_vers_lettre(int(x)) for x in resultat)


def dechiffrer_hill(cryptogramme: str, cle: np.ndarray) -> str:
    """Déchiffre un texte chiffré par Hill."""
    cle_inv = inverse_modulaire_matrice(cle)
    taille = cle.shape[0]
    
    # Convertir le cryptogramme en vecteurs
    vecteurs = []
    for i in range(0, len(cryptogramme), taille):
        bloc = cryptogramme[i:i+taille]
        vecteurs.append(np.array([lettre_vers_nombre(c) for c in bloc]))
    
    resultat = []
    for v in vecteurs:
        dechiffre = (cle_inv @ v) % MOD
        resultat.extend(dechiffre)
    
    return "".join(nombre_vers_lettre(int(x)) for x in resultat)


def attaque_clair_connu(clair_connu: str, chiffre_connu: str, taille: int = 2) -> np.ndarray:
    """
    Attaque à clair connu : retrouve la clé à partir de paires (clair, chiffré).
    Nécessite au moins 'taille' paires de blocs linéairement indépendants.
    """
    print("=" * 60)
    print("ATTAQUE À CLAIR CONNU - HILL")
    print("=" * 60)
    
    # Convertir en matrices
    n_blocs = len(clair_connu) // taille
    
    # Matrice du clair (P)
    P = []
    C = []
    for i in range(n_blocs):
        bloc_clair = clair_connu[i*taille:(i+1)*taille]
        bloc_chiffre = chiffre_connu[i*taille:(i+1)*taille]
        P.append([lettre_vers_nombre(c) for c in bloc_clair])
        C.append([lettre_vers_nombre(c) for c in bloc_chiffre])
    
    P = Matrix(P[:taille])  # Prendre 'taille' blocs pour former une matrice carrée
    C = Matrix(C[:taille])
    
    print(f"Matrice du clair P :\n{P}")
    print(f"Matrice du chiffré C :\n{C}")
    
    # K = C × P^(-1) mod 26
    try:
        P_inv = P.inv_mod(MOD)
        K = (C * P_inv) % MOD
        K = np.array(K, dtype=int)
        
        print(f"\nMatrice clé retrouvée K :\n{K}")
        
        # Vérification
        test_chiffre = chiffrer_hill(clair_connu[:taille*taille], K)
        print(f"\nVérification : chiffrement de '{clair_connu[:taille*taille]}'")
        print(f"  Résultat : {test_chiffre}")
        print(f"  Attendu  : {chiffre_connu[:taille*taille]}")
        print(f"  Match : {test_chiffre == chiffre_connu[:taille*taille]}")
        
        return K
        
    except Exception as e:
        print(f"Erreur : {e}")
        print("Les blocs choisis ne sont pas linéairement indépendants.")
        return None


# ============== DÉMONSTRATION ==============

if __name__ == "__main__":
    print("=" * 60)
    print("DÉMONSTRATION - CHIFFRE DE HILL (2×2)")
    print("=" * 60)
    
    # Clé 2×2 (doit être inversible mod 26)
    K2 = np.array([[3, 3],
                   [2, 5]])
    
    print(f"Matrice clé K (2×2) :\n{K2}")
    
    # Vérifier l'inversibilité
    try:
        K2_inv = inverse_modulaire_matrice(K2)
        print(f"Inverse mod 26 :\n{K2_inv}")
    except ValueError as e:
        print(f"Erreur : {e}")
        exit()
    
    message = "hillcipher"
    print(f"\nMessage : {message}")
    
    cryptogramme = chiffrer_hill(message, K2)
    print(f"Cryptogramme : {cryptogramme}")
    
    dechiffre = dechiffrer_hill(cryptogramme, K2)
    print(f"Déchiffré : {dechiffre}")
    
    # Attaque à clair connu
    print("\n" + "=" * 60)
    clair_connu = "hill"
    chiffre_connu = chiffrer_hill(clair_connu, K2)
    print(f"Clair connu  : {clair_connu}")
    print(f"Chiffré connu: {chiffre_connu}")
    
    K_retrouvee = attaque_clair_connu(clair_connu, chiffre_connu, taille=2)
    
    # Démonstration 3×3
    print("\n" + "=" * 60)
    print("DÉMONSTRATION - HILL (3×3)")
    print("=" * 60)
    
    K3 = np.array([[6, 24, 1],
                   [13, 16, 10],
                   [20, 17, 15]])
    
    message3 = "attackatdawn"
    print(f"Message : {message3}")
    
    crypto3 = chiffrer_hill(message3, K3)
    print(f"Cryptogramme : {crypto3}")
    
    dechiffre3 = dechiffrer_hill(crypto3, K3)
    print(f"Déchiffré : {dechiffre3}")
    
    # Attaque à clair connu 3×3
    clair3 = "attackat"
    chiffre3 = chiffrer_hill(clair3, K3)
    K3_retrouvee = attaque_clair_connu(clair3, chiffre3, taille=3)
    
    print(f"\n{'='*60}")
    print("QUESTION : Pourquoi Hill est vulnérable à l'attaque à clair connu")
    print(f"{'='*60}")
    print("""
    Hill est vulnérable car :
    1. Le chiffrement est linéaire : C = K × P mod 26
    2. Avec 'n' paires (clair, chiffré) linéairement indépendantes,
        on résout un système d'équations linéaires pour trouver K.
    3. Cela fonctionne même pour de grandes matrices car la
        vulnérabilité vient de la linéarité, pas de la taille.
    4. Contre-mesure : ajouter du non-linéarité (comme dans AES).
    """)