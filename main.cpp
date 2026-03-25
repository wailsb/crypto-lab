#include <iostream>
#include "Classiques/Cesar/cesar.h"
#include "Classiques/Hill/hill.h"
#include "Classiques/Affine/affine.h"
using namespace std;

void menu() {
    cout << "\n==== CRYPTO LAB ====\n";
    cout << "1. Caesar Encrypt\n";
    cout << "2. Caesar Decrypt\n";
    cout << "3. Hill Encrypt\n";
    cout << "4. Hill Decrypt\n";
    cout << "5. Affine Encrypt\n";
    cout << "6. Affine Decrypt\n";
    cout << "7. Exit\n";
    cout << "Choice: ";
}

int main() {
    int choice;
    string text;

    while (true) {
        menu();
        cin >> choice;

        if (choice == 4) break;

        cout << "Enter text: ";
        cin >> text;

        if (choice == 1) {
            cout << cesar_crypt(text, 3) << endl;
        }
        else if (choice == 2) {
            cout << cesar_decrypt(text, 3) << endl;
        }
        else if (choice == 3) {
            try {
                int n;
                cout << "Enter matrix size n: ";
                cin >> n;
                vector<vector<int>> keyMatrix(n, vector<int>(n));
                cout << "Enter " << n*n << " integers for the key matrix: ";
                for(int i = 0; i < n; i++) {
                    for(int j = 0; j < n; j++) {
                        cin >> keyMatrix[i][j];
                    }
                }
                string encrypted = hillEncrypt(text, keyMatrix);
                cout << "Encrypted: " << encrypted << endl;
            } catch (const exception& e) {
                cerr << "Error: " << e.what() << endl;
            }
        }
        else if (choice == 4) {
            try {
                int n;
                cout << "Enter matrix size n: ";
                cin >> n;
                vector<vector<int>> keyMatrix(n, vector<int>(n));
                cout << "Enter " << n*n << " integers for the key matrix: ";
                for(int i = 0; i < n; i++) {
                    for(int j = 0; j < n; j++) {
                        cin >> keyMatrix[i][j];
                    }
                }
                string decrypted = hillDecrypt(text, keyMatrix);
                cout << "Decrypted: " << decrypted << endl;
            } catch (const exception& e) {
                cerr << "Error: " << e.what() << endl;
            }
        }
        else if (choice == 5) {
            affine aff;
            aff.txtToCrypt = (char*)text.c_str();
            aff.a = 5; // example key
            aff.b = 8; // example key
            char* encrypted = affineCrypt(&aff);
            cout << "Encrypted: " << (encrypted + sizeof(int)) << endl;
            free(encrypted);
        }
        else if (choice == 6) {
            affine aff;
            aff.txtToCrypt = (char*)text.c_str();
            aff.a = 5; // example key
            aff.b = 8; // example key
            char* decrypted = affineDecryptOnlyAlph((affineDecryptStr*)&aff);
            cout << "Decrypted: " << decrypted << endl;
            free(decrypted);
        }
        else {
            cout << "Invalid choice. Try again." << endl;
        }
    }
}