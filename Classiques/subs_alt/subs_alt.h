#include <iostream>
#include <string>
#include <array>
#include <algorithm>
#include <cstdlib>
#include <ctime>
#include <cctype>
using namespace std;


string substitution_crypter(const string& texte, const array<char, 26>& table);
string substitution_decrypter(const string& texte, const array<char, 26>& inverse);

// Génère une table de substitution aléatoire pour les 26 lettres
array<char, 26> generer_table_substitution() {
    array<char, 26> table;
    for (int i = 0; i < 26; i++) table[i] = 'A' + i;
    // Mélange aléatoire (Fisher-Yates)
    for (int i = 25; i > 0; i--) {
        int j = rand() % (i + 1);
        swap(table[i], table[j]);
    }
    return table;
}

array<char, 26> inverser_table(const array<char, 26>& table) {
    array<char, 26> inverse;
    for (int i = 0; i < 26; i++) {
        inverse[table[i] - 'A'] = 'A' + i;
    }
    return inverse;
}
void afficher_table(const array<char, 26>& table) {
    cout << "Clair  : ";
    for (int i = 0; i < 26; i++) cout << (char)('A' + i) << " ";
    cout << "\nChiffre: ";
    for (char c : table) cout << c << " ";
    cout << endl;
}

