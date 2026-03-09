#include "affine.h" 
#include <iostream> 
#include <cstring> 
using namespace std;

// Function to encrypt the text using the affine cipher

char *affineCrypt(affine* aff) {
    while (gcd(aff->a, 26) != 1)
    {
            cout << "a and 26 are not coprime. Please enter a different value for a: ";
            cin >> aff->a;
    }
    
    char* cryptedTxt = (char *)malloc(strlen(aff->txtToCrypt) + 1);
    for (int i = 0; i < strlen(aff->txtToCrypt); i++)
    { 
        int position=(int)(aff->txtToCrypt[i]);
        char cryptedChar=(char)(((aff->a*position)+aff->b)%255);
        cryptedTxt[i] = cryptedChar;
    }
    
    cryptedTxt[strlen(aff->txtToCrypt)] = '\0';
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
        if(aff->txtToCrypt[i] < 'A' || aff->txtToCrypt[i] > 'Z') {
            position = (aff->txtToCrypt[i]-'A');
        }else if(aff->txtToCrypt[i] < 'a' || aff->txtToCrypt[i] > 'z') {
            position = (aff->txtToCrypt[i]-'a');
            isUpper=false;
        }else {
            cryptedTxt[0] = '\0';
            return cryptedTxt;
        }
        char cryptedChar=(char)(((aff->a*(position+(isUpper? 'A' : 'a')))+aff->b)%26+(isUpper? 'A' : 'a'));
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
    bool isDecryptable = (gcd(decaff->a, 255) == 1);
    if(!isDecryptable) {
        char* decryptedTxt = (char *)malloc(sizeof(char));
        decryptedTxt[0] = '\0';
        return decryptedTxt;
    }
    int a_inv = modInv(decaff->a, 255);
    char* decryptedTxt = (char *)malloc(strlen(decaff->txtToDecrypt) + 1);
    for (int i = 0; i < strlen(decaff->txtToDecrypt); i++)
    { 
        int position=(int)(decaff->txtToDecrypt[i]);
        char decryptedChar=(char)((a_inv*(position-decaff->b))%255);
        decryptedTxt[i] = decryptedChar;
    }

    return decryptedTxt;
}
char *affineDecryptOnlyAlph(affineDecryptStr* decaff){
    return nullptr;
}

int main() {
    cout << "Hello, affine algo cryptage!" << endl;
    affine aff;
    char *cryptedTxt=(char *)malloc(sizeof(char));
    aff.txtToCrypt = (char*)"wailsaribey";
    aff.a = 5;
    aff.b = 8;
    cryptedTxt = affineCryptOnlyAlph(&aff);
    cout << "Crypted text: " << cryptedTxt << endl;
    free(cryptedTxt);
    return 0;
}