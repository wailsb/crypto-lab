#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <algorithm>
using namespace std;

//chatgpt

char grille[5][5];
int pos_ligne[26], pos_col[26];

void construire_grille(const string& cle) {
    bool utilise[26] = {};
    utilise['J' - 'A'] = true; // J fusionné avec I

    string seq = "";
    for (char c : cle) {
        c = toupper(c);
        if (!isalpha(c)) continue;
        if (c == 'J') c = 'I';
        if (!utilise[c - 'A']) {
            utilise[c - 'A'] = true;
            seq += c;
        }
    }
    for (int i = 0; i < 26; i++) {
        if (!utilise[i]) seq += (char)('A' + i);
    }

    int k = 0;
    for (int r = 0; r < 5; r++)
        for (int c = 0; c < 5; c++) {
            grille[r][c] = seq[k];
            pos_ligne[seq[k] - 'A'] = r;
            pos_col [seq[k] - 'A'] = c;
            k++;
        }
}

void afficher_grille() {
    cout << "\nGrille Playfair :" << endl;
    cout << "+---+---+---+---+---+" << endl;
    for (int r = 0; r < 5; r++) {
        cout << "| ";
        for (int c = 0; c < 5; c++)
            cout << grille[r][c] << " | ";
        cout << "\n+---+---+---+---+---+" << endl;
    }
}

string preparer_texte(const string& texte) {
    string t = "";
    for (char c : texte) {
        if (!isalpha(c)) continue;
        c = toupper(c);
        if (c == 'J') c = 'I';
        t += c;
    }

    string resultat = "";
    int i = 0;
    while (i < t.size()) {
        char a = t[i];
        char b = (i + 1 < t.size()) ? t[i + 1] : 'X';

        if (a == b) {
            resultat += a;
            resultat += 'X';
            i++;
        } else {
            resultat += a;
            resultat += b;
            i += 2;
        }
    }
    if (resultat.size() % 2 != 0) resultat += 'X';
    return resultat;
}

pair<char,char> traiter_digramme(char a, char b, int sens) {
    // sens = +1 (chiffrer), -1 (déchiffrer)
    int ra = pos_ligne[a - 'A'], ca = pos_col[a - 'A'];
    int rb = pos_ligne[b - 'A'], cb = pos_col[b - 'A'];

    char na, nb;

    if (ra == rb) {
        // Même ligne → décaler colonnes
        na = grille[ra][(ca + sens + 5) % 5];
        nb = grille[rb][(cb + sens + 5) % 5];
    } else if (ca == cb) {
        // Même colonne → décaler lignes
        na = grille[(ra + sens + 5) % 5][ca];
        nb = grille[(rb + sens + 5) % 5][cb];
    } else {
        // Rectangle → échanger colonnes
        na = grille[ra][cb];
        nb = grille[rb][ca];
    }
    return {na, nb};
}

string playfair_chiffrer(const string& texte) {
    string prep = preparer_texte(texte);
    string resultat = "";
    for (int i = 0; i < prep.size(); i += 2) {
        auto [a, b] = traiter_digramme(prep[i], prep[i+1], +1);
        resultat += a;
        resultat += b;
    }
    return resultat;
}

string playfair_dechiffrer(const string& chiffre) {
    string resultat = "";
    for (int i = 0; i < chiffre.size(); i += 2) {
        auto [a, b] = traiter_digramme(chiffre[i], chiffre[i+1], -1);
        resultat += a;
        resultat += b;
    }
    return resultat;
}

int main() {
    string texte, cle;

    cout << "=== Chiffre de Playfair ===" << endl;
    cout << "Entrez la cle   : ";
    getline(cin, cle);
    cout << "Entrez le texte : ";
    getline(cin, texte);

    construire_grille(cle);
    afficher_grille();

    string prep      = preparer_texte(texte);
    string chiffre   = playfair_chiffrer(texte);
    string dechiffre = playfair_dechiffrer(chiffre);

    cout << "\nTexte prepare   : " << prep      << endl;
    cout << "Texte chiffre   : " << chiffre   << endl;
    cout << "Texte dechiffre : " << dechiffre << endl;

    return 0;
}