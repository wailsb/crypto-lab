"""
TP1 - Exercice 1.2 : Chiffre de Vigenère
Implémentation, test de Kasiski, analyse par IC
"""

import string
from collections import Counter, defaultdict
import math

ALPHABET = string.ascii_lowercase
IC_FRANCAIS = 0.074


def chiffrer_vigenere(texte: str, cle: str) -> str:
    """Chiffre un texte avec Vigenère."""
    texte = [c for c in texte.lower() if c in ALPHABET]
    cle = cle.lower()
    
    resultat = []
    for i, c in enumerate(texte):
        k = ALPHABET.index(cle[i % len(cle)])
        idx = (ALPHABET.index(c) + k) % 26
        resultat.append(ALPHABET[idx])
    
    return "".join(resultat)


def dechiffrer_vigenere(texte: str, cle: str) -> str:
    """Déchiffre un texte chiffré par Vigenère."""
    cle = cle.lower()
    resultat = []
    for i, c in enumerate(texte):
        k = ALPHABET.index(cle[i % len(cle)])
        idx = (ALPHABET.index(c) - k) % 26
        resultat.append(ALPHABET[idx])
    return "".join(resultat)


def test_kasiski(cryptogramme: str, longueur_min: int = 3, longueur_max: int = 5) -> dict:
    """
    Test de Kasiski : recherche de trigrammes répétés.
    Retourne les distances entre répétitions pour estimer la longueur de clé.
    """
    print("=" * 60)
    print("TEST DE KASISKI")
    print("=" * 60)
    
    # Trouver tous les n-grammes répétés
    repetitions = defaultdict(list)
    
    for n in range(longueur_min, longueur_max + 1):
        for i in range(len(cryptogramme) - n + 1):
            ngram = cryptogramme[i:i+n]
            repetitions[ngram].append(i)
    
    # Filtrer les n-grammes répétés
    repetitions = {k: v for k, v in repetitions.items() if len(v) >= 2}
    
    distances = []
    print("\nN-grammes répétés et distances :")
    for ngram, positions in repetitions.items():
        if len(positions) >= 2:
            print(f"  '{ngram}' aux positions {positions}")
            for i in range(len(positions) - 1):
                for j in range(i + 1, len(positions)):
                    dist = positions[j] - positions[i]
                    distances.append(dist)
                    print(f"    Distance = {dist}")
    
    # Calculer les PGCD des distances
    if distances:
        print(f"\nDistances trouvées : {distances}")
        # Estimer la longueur de clé par les diviseurs communs
        compteurs = Counter()
        for d in distances:
            for diviseur in range(2, min(d + 1, 20)):
                if d % diviseur == 0:
                    compteurs[diviseur] += 1
        
        print("\nDiviseurs fréquents (candidats pour |K|) :")
        for div, freq in compteurs.most_common(5):
            print(f"  |K| = {div}: apparu {freq} fois")
    
    return repetitions


def calculer_ic(texte: str) -> float:
    """Calcule l'indice de coïncidence."""
    texte = [c for c in texte if c in ALPHABET]
    N = len(texte)
    if N <= 1:
        return 0.0
    compteur = Counter(texte)
    return sum(n * (n - 1) for n in compteur.values()) / (N * (N - 1))


def attaque_ic_vigenere(cryptogramme: str, longueur_max: int = 15) -> str:
    """
    Attaque par IC : détermine la longueur de clé puis retrouve chaque lettre.
    """
    print("\n" + "=" * 60)
    print("ATTAQUE PAR IC - VIGENÈRE")
    print("=" * 60)
    
    # Étape 1 : Estimer la longueur de clé
    print("\n--- Étape 1 : Estimation de la longueur de clé ---")
    
    meilleur_ic_moyen = 0
    meilleure_longueur = 1
    
    for k in range(1, longueur_max + 1):
        # Découper en k sous-séquences
        sous_sequences = [[] for _ in range(k)]
        for i, c in enumerate(cryptogramme):
            if c in ALPHABET:
                sous_sequences[i % k].append(c)
        
        # Calculer IC moyen
        ics = [calculer_ic("".join(seq)) for seq in sous_sequences if seq]
        ic_moyen = sum(ics) / len(ics) if ics else 0
        
        indicateur = " <<< PROBABLE" if abs(ic_moyen - IC_FRANCAIS) < 0.01 else ""
        print(f"  k={k:2d}: IC moyen = {ic_moyen:.4f}{indicateur}")
        
        # On cherche l'IC le plus proche de celui du français
        if abs(ic_moyen - IC_FRANCAIS) < abs(meilleur_ic_moyen - IC_FRANCAIS):
            meilleur_ic_moyen = ic_moyen
            meilleure_longueur = k
    
    print(f"\n>>> Longueur de clé estimée : {meilleure_longueur}")
    
    # Étape 2 : Retrouver chaque lettre de la clé par analyse de fréquences
    print(f"\n--- Étape 2 : Retrouver les lettres de la clé ---")
    
    cle_trouvee = []
    
    for pos in range(meilleure_longueur):
        # Extraire la sous-séquence
        sous_seq = [cryptogramme[i] for i in range(pos, len(cryptogramme), meilleure_longueur)
                    if cryptogramme[i] in ALPHABET]
        sous_seq = "".join(sous_seq)
        
        # Analyser les fréquences
        compteur = Counter(sous_seq)
        total = len(sous_seq)
        
        # La lettre la plus fréquente en français est 'e'
        # On suppose que la lettre la plus fréquente correspond à 'e'
        lettre_plus_frequente = compteur.most_common(1)[0][0]
        
        # Déduire la clé : (lettre_chiffrée - 'e') mod 26
        k = (ALPHABET.index(lettre_plus_frequente) - ALPHABET.index('e')) % 26
        cle_trouvee.append(ALPHABET[k])
        
        print(f"  Position {pos}: sous-séquence = '{sous_seq[:20]}...'")
        print(f"    Lettre la plus fréquente : '{lettre_plus_frequente}'")
        print(f"    Lettre de clé déduite : '{ALPHABET[k]}' (décalage de {k})")
    
    cle = "".join(cle_trouvee)
    print(f"\n>>> Clé trouvée : '{cle}'")
    
    # Déchiffrer
    dechiffre = dechiffrer_vigenere(cryptogramme, cle)
    print(f">>> Texte déchiffré : {dechiffre[:100]}...")
    
    return cle


# ============== DÉMONSTRATION ==============

if __name__ == "__main__":
    message = "lechiffredevigenereestplussecurisequecesarmaisrestevulnerablealalanalysedesfrequenceslongueurdelacle"
    cle = "crypto"
    
    print("=" * 60)
    print("DÉMONSTRATION - CHIFFRE DE VIGENÈRE")
    print("=" * 60)
    print(f"Message : {message[:60]}...")
    print(f"Clé     : '{cle}' (longueur = {len(cle)})")
    
    cryptogramme = chiffrer_vigenere(message, cle)
    print(f"\nCryptogramme : {cryptogramme[:80]}...")
    
    # Test de Kasiski
    test_kasiski(cryptogramme)
    
    # Attaque par IC
    cle_trouvee = attaque_ic_vigenere(cryptogramme)
    
    # Vérification
    print(f"\n{'='*60}")
    print("VÉRIFICATION")
    print(f"Clé réelle : '{cle}'")
    print(f"Clé trouvée : '{cle_trouvee}'")
    print(f"Match : {cle == cle_trouvee}")
    
    # Question : impact de la longueur de clé
    print(f"\n{'='*60}")
    print("QUESTION : Impact de la longueur de la clé")
    print(f"{'='*60}")
    print("""
    - Si |K| << |M| : Le chiffre est vulnérable à Kasiski et IC car
      des motifs se répètent périodiquement.
    - Si |K| = |M| (et clé aléatoire) : On obtient un OTP (One-Time Pad)
      qui est théoriquement parfaitement sûr. Chaque lettre du message
      est chiffrée avec une lettre unique de la clé, éliminant toute
      structure statistique exploitable.
    - Si |K| > |M| : Inutile, seuls les |M| premiers caractères servent.
    """)