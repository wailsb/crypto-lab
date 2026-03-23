#include <iostream>
#include "cesar.h"
using namespace std;
//la formule que j'utilise est : C = (P + k) mod 26 kayenha fl cour 
//ou dechiffrement : P = (C - k) mod 26

std::string cesar_crypt(const std::string& plaintext, int k) {
    std::string c = "";
    for (char p : plaintext) {
        if (isalpha(p)) {
            char base = isupper(p) ? 'A' : 'a';
            c += (p - base + k) % 26 + base;
        } else {
            c += p; // Non-alphabetic characters are unchanged
        }
    }
    return c;
}

std::string cesar_decrypt(const std::string& ciphertext, int k) {
    std::string c = "";
    for (char p : ciphertext) {
        if (isalpha(p)) {
            char base = isupper(p) ? 'A' : 'a';
            c += (p - base - k + 26) % 26 + base;
        } else {
            c += p; // Non-alphabetic characters are unchanged
        }
    }
    return c;
}

//char base = isupper(p) ? 'A' : 'a'; hadi l7aja li t3tina ila l7arf kbir wla sghir
//bach n3rfou ch7al kayn f alphabet w n9adro ndirou 3lih les operations dyalna

int main() {
    string texte  = "Hello World";
    int cle       = 3;

    string chiffre = cesar_crypt(texte, cle);
    string decode  = cesar_decrypt(chiffre, cle);

    cout << "Clair   : " << texte   << endl;
    cout << "Chiffre : " << chiffre << endl;
    cout << "Decode  : " << decode  << endl;

    return 0;
}