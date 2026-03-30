#include <iostream>
#include <string>
#include <cctype>
#include "vignere.h"
using namespace std;

string vigenere_crypter(const string& texte, const string& cle) {
    string c = "";
    int j = 0;
    for (int i = 0; i < texte.size(); i++) {
        char p = texte[i];
        if (isalpha(p)) {
            char base = isupper(p) ? 'A' : 'a';
            int decalage = toupper(cle[j % cle.size()]) - 'A';
            c += (char)((p - base + decalage) % 26 + base);
            j++;
        } else {
            c += p;
        }
    }
    return c;
}

string vigenere_decrypter(const string& texte, const string& cle) {
    string resultat = "";
    int j = 0;
    for (int i = 0; i < texte.size(); i++) {
        char c = texte[i];
        if (isalpha(c)) {
            char base = isupper(c) ? 'A' : 'a';
            int decalage = toupper(cle[j % cle.size()]) - 'A';
            resultat += (char)((c - base - decalage + 26) % 26 + base);
            j++;
        } else {
            resultat += c;
        }
    }
    return resultat;
}

int main() {
    string texte, cle;

    cout << "=== Chiffre de Vigenere ===" << endl;
    cout << "Entrez le texte : ";
    getline(cin, texte);
    cout << "Entrez la cle   : ";
    getline(cin, cle);

    string chiffre   = vigenere_crypter(texte, cle);
    string dechiffre = vigenere_decrypter(chiffre, cle);

    cout << "\nTexte original  : " << texte    << endl;
    cout << "Texte chiffre   : " << chiffre   << endl;
    cout << "Texte dechiffre : " << dechiffre << endl;

    return 0;
}