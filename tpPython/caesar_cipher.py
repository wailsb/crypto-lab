"""
TP1 - Exercice 1.1 : Chiffre de César
Implémentation, attaque par force brute, analyse de fréquences
"""

import string
from collections import Counter

# Alphabet standard (26 lettres)
ALPHABET = string.ascii_lowercase

# Fréquences standard du français (approximatif)
FREQ_FR = {
    'a': 0.0815, 'b': 0.0097, 'c': 0.0315, 'd': 0.0373, 'e': 0.1739,
    'f': 0.0112, 'g': 0.0085, 'h': 0.0074, 'i': 0.0731, 'j': 0.0045,
    'k': 0.0001, 'l': 0.0568, 'm': 0.0287, 'n': 0.0712, 'o': 0.0528,
    'p': 0.0280, 'q': 0.0121, 'r': 0.0664, 's': 0.0814, 't': 0.0722,
    'u': 0.0638, 'v': 0.0164, 'w': 0.0003, 'x': 0.0042, 'y': 0.0014,
    'z': 0.0032
}

# IC du français ≈ 0.074
IC_FRANCAIS = 0.074

# Dictionnaire de mots courants français (simplifié)
MOTS_COURANTS = [
    "le", "la", "de", "et", "un", "une", "en", "que", "qui", "dans",
    "pour", "par", "sur", "avec", "sans", "sous", "est", "sont", "les",
    "des", "ces", "ses", "mon", "ton", "son", "notre", "votre", "leur",
    "ce", "se", "ne", "pas", "plus", "tout", "tous", "toute", "toutes",
    "comme", "mais", "ou", "ou", "donc", "car", "ni", "or", "que",
    "bonjour", "merci", "salut", "bonsoir", "aujourd", "hui", "demain",
    "hier", "matin", "soir", "jour", "nuit", "temps", "heure", "minute",
    "chiffre", "texte", "message", "secret", "cle", "code", "crypte",
    "bon", "mauvais", "grand", "petit", "beau", "belle", "nouveau",
    "ancien", "jeune", "vieux", "homme", "femme", "enfant", "fille",
    "garcon", "ami", "amie", "amour", "paix", "guerre", "vie", "mort"
]


def chiffrer_cesar(texte: str, k: int) -> str:
    """Chiffre un texte avec le chiffre de César (décalage k)."""
    texte = texte.lower()
    resultat = []
    for c in texte:
        if c in ALPHABET:
            idx = (ALPHABET.index(c) + k) % 26
            resultat.append(ALPHABET[idx])
        # Ignorer les espaces et la ponctuation
    return "".join(resultat)


def dechiffrer_cesar(texte: str, k: int) -> str:
    """Déchiffre un texte chiffré par César."""
    return chiffrer_cesar(texte, -k)


def attaque_force_brute(cryptogramme: str, seuil_mots: int = 3) -> list:
    """
    Attaque par force brute : teste les 26 clés possibles.
    Retourne les candidats probables avec un score.
    """
    print("=" * 60)
    print("ATTAQUE PAR FORCE BRUTE - CÉSAR")
    print("=" * 60)
    
    candidats = []
    
    for k in range(26):
        dechiffre = dechiffrer_cesar(cryptogramme, k)
        # Compte combien de mots courants apparaissent
        mots_trouves = sum(1 for mot in MOTS_COURANTS if mot in dechiffre)
        score = mots_trouves
        
        candidats.append((k, dechiffre, score))
        
        indicateur = " <<< PROBABLE" if score >= seuil_mots else ""
        print(f"Clé k={k:2d}: {dechiffre[:50]:50s} | Score={score}{indicateur}")
    
    # Trier par score décroissant
    candidats.sort(key=lambda x: x[2], reverse=True)
    
    print(f"\n>>> Meilleur candidat : k={candidats[0][0]}")
    print(f">>> Texte : {candidats[0][1]}")
    
    return candidats


def calculer_ic(texte: str) -> float:
    """
    Calcule l'Indice de Coïncidence (IC) d'un texte.
    IC = Σ(ni × (ni-1)) / (N × (N-1)) où ni = fréquence de la lettre i
    """
    texte = [c for c in texte.lower() if c in ALPHABET]
    N = len(texte)
    if N <= 1:
        return 0.0
    
    compteur = Counter(texte)
    ic = sum(n * (n - 1) for n in compteur.values()) / (N * (N - 1))
    return ic


def attaque_ic(cryptogramme: str) -> int:
    """
    Attaque par analyse de fréquences utilisant l'IC.
    Compare les fréquences du cryptogramme avec celles du français.
    """
    print("\n" + "=" * 60)
    print("ATTAQUE PAR INDICE DE COÏNCIDENCE")
    print("=" * 60)
    
    # IC du cryptogramme
    ic_crypto = calculer_ic(cryptogramme)
    print(f"IC du cryptogramme : {ic_crypto:.4f}")
    print(f"IC du français     : {IC_FRANCAIS:.4f}")
    
    # Calculer les fréquences du cryptogramme
    texte = [c for c in cryptogramme.lower() if c in ALPHABET]
    compteur = Counter(texte)
    total = len(texte)
    
    freq_crypto = {lettre: compteur.get(lettre, 0) / total for lettre in ALPHABET}
    
    # Tester chaque décalage et calculer la corrélation
    meilleure_correlation = -1
    meilleur_k = 0
    
    print("\nCorrélation pour chaque décalage k :")
    for k in range(26):
        correlation = 0.0
        for lettre in ALPHABET:
            lettre_dechiffree = ALPHABET[(ALPHABET.index(lettre) - k) % 26]
            correlation += freq_crypto[lettre] * FREQ_FR.get(lettre_dechiffree, 0)
        
        print(f"  k={k:2d}: corrélation = {correlation:.6f}")
        
        if correlation > meilleure_correlation:
            meilleure_correlation = correlation
            meilleur_k = k
    
    print(f"\n>>> Clé déduite par IC : k={meilleur_k}")
    print(f">>> Texte déchiffré : {dechiffrer_cesar(cryptogramme, meilleur_k)}")
    
    return meilleur_k


# ============== DÉMONSTRATION ==============

if __name__ == "__main__":
    # Message original
    message = "lechiffredecesarestfacileacasseraveclanalysedesfrequences"
    
    print("=" * 60)
    print("DÉMONSTRATION - CHIFFRE DE CÉSAR")
    print("=" * 60)
    print(f"Message original : {message}")
    
    # Chiffrement avec k=7
    k = 7
    cryptogramme = chiffrer_cesar(message, k)
    print(f"\nCryptogramme (k={k}) : {cryptogramme}")
    
    # Déchiffrement
    dechiffre = dechiffrer_cesar(cryptogramme, k)
    print(f"Déchiffré (k={k})   : {dechiffre}")
    
    # Attaque par force brute
    attaque_force_brute(cryptogramme)
    
    # Attaque par IC
    attaque_ic(cryptogramme)