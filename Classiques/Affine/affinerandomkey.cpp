#include "affine.h"
#include <iostream>
#include <cstring>
#include <cstdlib>  // rand, srand
#include <ctime>    // time
using namespace std;

void generateRandomKeys(int& a, int& b) {
    srand(time(NULL));  // seed aleatoire basé sur l'heure
    
    // liste des valeurs valides pour a (copremiers avec 26)
    int validA[] = {1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25};
    int size = sizeof(validA) / sizeof(validA[0]);
    
    a = validA[rand() % size];       // choisit un a valide aleatoirement
    b = rand() % 26;                 // b entre 0 et 25
}

// Function to encrypt the text using the affine cipher
char *affineCrypt(affine* aff) {
    while (gcd(aff->a, 26) != 1)
    {
        cout << "a and 26 are not coprime. Please enter a different value for a: ";
        cin >> aff->a;
    }
    int txtLen = strlen(aff->txtToCrypt);
    char* cryptedTxt = (char *)malloc(sizeof(int) + txtLen + 1);
    *(int*)cryptedTxt = txtLen;
    char* dst = cryptedTxt + sizeof(int);
    for (int i = 0; i < txtLen; i++)
    { 
        int position=(int)(unsigned char)(aff->txtToCrypt[i]);
        dst[i]=(char)(((aff->a*position)+aff->b)%256);
    }
    dst[txtLen] = '\0';
    return cryptedTxt;
}
// Function to encrypt only the alphabetic characters in the text using the affine cipher
char *affineCryptOnlyAlph(affine* aff) {
    while (gcd(aff->a,26)!=1)
    {
        cout << "a and 26 are not coprime. Please enter a different value for a: ";
        cin >> aff->a;
    }
    char* cryptedTxt = (char *)malloc(strlen(aff->txtToCrypt) + 1);
    int position;
    bool isUpper=true;
    for (int i = 0; i < strlen(aff->txtToCrypt); i++)
    { 
        if(aff->txtToCrypt[i] >= 'A' && aff->txtToCrypt[i] <= 'Z') {
            position = (aff->txtToCrypt[i]-'A');
            isUpper=true;
        }else if(aff->txtToCrypt[i] >= 'a' && aff->txtToCrypt[i] <= 'z') {
            position = (aff->txtToCrypt[i]-'a');
            isUpper=false;
        }else {
            // non-alpha: keep as-is
            cryptedTxt[i] = aff->txtToCrypt[i];
            continue;
        }
        char cryptedChar=(char)(((aff->a*position)+aff->b)%26+(isUpper? 'A' : 'a'));
        cryptedTxt[i] = cryptedChar;
    }
    cryptedTxt[strlen(aff->txtToCrypt)] = '\0';
    return cryptedTxt;
}
// utils
int gcd(int a, int b) {
    if (b == 0)
        return a;
    return gcd(b, a % b);
}
int modInv(int a, int m) {
    a = a % m;
    for (int x = 1; x < m; x++) {
        if ((a * x) % m == 1)
            return x;
    }
    return -1; 
}
// decrypting functions ::
char *affineDecrypt(affineDecryptStr* decaff){
    bool isDecryptable = (gcd(decaff->a, 256) == 1);
    if(!isDecryptable) {
        char* decryptedTxt = (char *)malloc(sizeof(char));
        decryptedTxt[0] = '\0';
        return decryptedTxt;
    }
    int a_inv = modInv(decaff->a, 256);
    int len = *(int*)decaff->txtToDecrypt;
    char* src = decaff->txtToDecrypt + sizeof(int);
    char* decryptedTxt = (char *)malloc(len + 1);
    for (int i = 0; i < len; i++)
    { 
        int position=(int)(unsigned char)(src[i]);
        int val = (a_inv * (position - decaff->b)) % 256;
        if(val < 0) val += 256;
        decryptedTxt[i] = (char)val;
    }
    decryptedTxt[len] = '\0';
    return decryptedTxt;
}
char *affineDecryptOnlyAlph(affineDecryptStr* decaff){
    bool isDecryptable = (gcd(decaff->a, 26) == 1);
    if(!isDecryptable) {
        char* decryptedTxt = (char *)malloc(sizeof(char));
        decryptedTxt[0] = '\0';
        return decryptedTxt;
    }
    int a_inv = modInv(decaff->a, 26);
    char* decryptedTxt = (char *)malloc(strlen(decaff->txtToDecrypt) + 1);
    bool isUpper=true;
    for (int i = 0; i < strlen(decaff->txtToDecrypt); i++)
    {
        int position;
        if(decaff->txtToDecrypt[i] >= 'A' && decaff->txtToDecrypt[i] <= 'Z') {
            position = decaff->txtToDecrypt[i]-'A';
            isUpper=true;
        }else if(decaff->txtToDecrypt[i] >= 'a' && decaff->txtToDecrypt[i] <= 'z') {
            position = decaff->txtToDecrypt[i]-'a';
            isUpper=false;
        }else {
            // non-alpha: keep as-is
            decryptedTxt[i] = decaff->txtToDecrypt[i];
            continue;
        }
        char decryptedChar=(char)((a_inv*(position-decaff->b+26))%26+(isUpper? 'A' : 'a'));
        decryptedTxt[i] = decryptedChar;
    }
    decryptedTxt[strlen(decaff->txtToDecrypt)] = '\0';
    return decryptedTxt;
}
int main() {
    cout << "Hello, affine algo cryptage!" << endl;
    affine aff;
    char *cryptedTxt=(char *)malloc(sizeof(char));
    aff.txtToCrypt = (char*)"wailsaribey";
    cout << "Text to encrypt and decrypt: " << aff.txtToCrypt << endl;
    aff.a = 5;
    aff.b = 8;
    cryptedTxt = affineCrypt(&aff);
    cout << "Crypted text: " << (cryptedTxt + sizeof(int)) << endl;
    affineDecryptStr decaff;
    decaff.txtToDecrypt = cryptedTxt;
    decaff.a = aff.a;
    decaff.b = aff.b;
    char* decryptedTxt = affineDecrypt(&decaff);
    cout << "Decrypted text: " << decryptedTxt << endl;
    free(cryptedTxt);
    free(decryptedTxt);
    return 0;
}
