#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <ctime>
#include "otp.h"
using namespace std;

// Génère une clé OTP aléatoire de la même taille que le texte (octets 0-255)
vector<int> generer_cle_otp(int taille) {
    vector<int> cle(taille);
    for (int i = 0; i < taille; i++) {
        cle[i] = rand() % 256;
    }
    return cle;
}

string otp_crypter(const string& texte, const vector<int>& cle) {
    string resultat = texte;
    for (int i = 0; i < texte.size(); i++) {
        resultat[i] = (unsigned char)texte[i] ^ cle[i];
    }
    return resultat;
}

// Le déchiffrement OTP est identique au chiffrement (XOR est sa propre inverse)
string otp_decrypter(const string& chiffre, const vector<int>& cle) {
    return otp_crypter(chiffre, cle);
}

void afficher_hex(const string& s) {
    for (unsigned char c : s) {
        printf("%02X ", c);
    }
    cout << endl;
}

int main() {
    srand(time(0));

    string texte;
    cout << "=== One-Time Pad (OTP) ===" << endl;
    cout << "Entrez le texte : ";
    getline(cin, texte);

    vector<int> cle = generer_cle_otp(texte.size());

    cout << "\nCle OTP (hex)   : ";
    for (int k : cle) printf("%02X ", k);
    cout << endl;

    string chiffre   = otp_crypter(texte, cle);
    string dechiffre = otp_decrypter(chiffre, cle);

    cout << "Texte chiffre   (hex) : ";
    afficher_hex(chiffre);
    cout << "Texte dechiffre : " << dechiffre << endl;

    return 0;
}