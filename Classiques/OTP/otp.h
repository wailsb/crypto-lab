#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <ctime>
using namespace std;
vector<int> generer_cle_otp(int taille);
string otp_crypter(const string& texte, const vector<int>& cle);
string otp_decrypter(const string& chiffre, const vector<int>& cle);
void afficher_hex(const string& s);