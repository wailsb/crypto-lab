# Crypto Lab

Crypto Lab est un projet académique réalisé en C++ dans le cadre de la 3ᵉ année d’ingénierie en sécurité informatique.
Il vise à implémenter et étudier différents algorithmes de chiffrement classiques, symétriques et asymétriques.

## Objectifs du projet

* Comprendre les principes fondamentaux de la cryptographie
* Implémenter des algorithmes de chiffrement de base
* Comparer les différentes approches cryptographiques
* Renforcer les compétences en programmation C++

## Structure du projet

```plaintext
/Classiques
    - Cesar
    - Hill
    - Playfair
    - Vigenere
    - Affine
    - Substitution
    - OTP
    - AnalyseFrequence

/Symetriques
/Asymetriques

main.cpp
README.md
```

## Algorithmes implémentés

### Chiffrement de César

Algorithme de substitution monoalphabétique basé sur un décalage fixe.

Formule :
C = (P + k) mod 26

---

### Chiffrement Affine

Extension du chiffrement de César utilisant une transformation linéaire.

Formule :
C = (aP + b) mod 26

Conditions :

* a ∈ ℤ et pgcd(a, 26) = 1
* b ∈ ℤ

---

*(Les autres algorithmes seront ajoutés progressivement.)*

## Attaques

### Attaque sur le chiffrement de César (`pythonAttacks/cesarattack.py`)

Script Python implémentant une attaque par force brute sur le chiffrement de César.
Teste les 26 décalages possibles et affiche les textes déchiffrés correspondants.
```bash
python pythonAttacks/cesarattack.py
```

## Tests

### Tests du chiffrement de César (`Tests/cesartest.cpp`)

Fichier de tests unitaires en C++ vérifiant le comportement du chiffrement de César
(chiffrement, déchiffrement, cas limites).
```bash
g++ Tests/cesartest.cpp -o cesartest
./cesartest
```

## Compilation

```bash
g++ main.cpp -o crypto
```

## Exécution

```bash
./crypto-lab
```

## Auteurs

* Sara Benbraham
* Wail Oueis Saribey

## Niveau

3ᵉ année – Ingénierie en Sécurité Informatique
