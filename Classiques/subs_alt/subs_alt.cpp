#include <iostream>
#include <string>
#include <array>
#include <algorithm>
#include <cstdlib>
#include <ctime>
#include <cctype>
#include "subs_alt.h"
using namespace std;

//en gros substitution aléatoire hiya thkm une table aleatoire (hna rni dyrtha randome, ila habit zid tae table fixe zid)
//



string substitution_crypter(const string& texte, const array<char, 26>& table) {
    string resultat = "";
    for (char c : texte) {
        if (isalpha(c)) {
            char base  = isupper(c) ? 'A' : 'a';
            char subs  = table[toupper(c) - 'A'];//toupper
            resultat  += isupper(c) ? subs : (char)(subs - 'A' + 'a');//had 
        } else {
            resultat += c;
        }
    }
    return resultat;
}


string substitution_decrypter(const string& texte, const array<char, 26>& inverse) {
    return substitution_crypter(texte, inverse);
}//win tchof hdi tae sens inverse medhali vscode


int main() {
    srand(time(0));

    string texte;
    cout << "=== Substitution Aleatoire ===" << endl;
    cout << "Entrez le texte : ";
    getline(cin, texte);

    array<char, 26> table   = generer_table_substitution();
    array<char, 26> inverse = inverser_table(table);

    cout << "\nTable de substitution :" << endl;
    afficher_table(table);

    string chiffre   = substitution_crypter(texte, table);
    string dechiffre = substitution_decrypter(chiffre, inverse);

    cout << "\nTexte original  : " << texte    << endl;
    cout << "Texte chiffre   : " << chiffre   << endl;
    cout << "Texte dechiffre : " << dechiffre << endl;

    return 0;
}