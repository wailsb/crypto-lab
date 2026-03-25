#include <iostream>
#include "hill.h"
#include <vector>
using namespace std;


string hillEncrypt(const string& text, const vector<vector<int>>& keyMatrix){
    int size = keyMatrix.size();
    string textcrypte = "";
    for (size_t i = 0; i < text.size(); i += size) { // traiter le texte par blocs de la taille de la matrice clé
        vector<int> block(size, 0); // block de taille égale à la taille de la matrice clé
        for (size_t j = 0; j < size; ++j) { // remplir le block avec les caractères du texte convertis en indices (A=0, B=1, ..., Z=25)
            if (i + j < text.size()) {// vérifier que nous ne dépassons pas la taille du texte
                block[j] = text[i + j] - 'A';//
            }
        }
        for (size_t k = 0; k < size; ++k) {// calculer le caractère chiffré pour la position k en multipliant la matrice clé par le block
            int sum = 0;
            for (size_t j = 0; j < size; ++j) {
                sum += keyMatrix[k][j] * block[j];
            }
            textcrypte += (sum % 26) + 'A';
        }
    }
    return textcrypte;
}

int modInverse(int a, int m){
    a = a % m;
    for (int x = 1; x < m; x++) {
        if ((a * x) % m == 1)
            return x;
    }
}
int determinant(const vector<vector<int>>& matrix){
    int det = 0;
    if (matrix.size() == 1) {
        return matrix[0][0];
    }
    for (size_t col = 0; col < matrix[0].size(); ++col) {
        vector<vector<int>> subMatrix(matrix.size() - 1, vector<int>(matrix[0].size() - 1));
        for (size_t i = 1; i < matrix.size(); ++i) {
            for (size_t j = 0; j < matrix[0].size(); ++j) {
                if (j < col) {
                    subMatrix[i - 1][j] = matrix[i][j];
                } else if (j > col) {
                    subMatrix[i - 1][j - 1] = matrix[i][j];
                }
            }
        }
        det += (col % 2 == 0 ? 1 : -1) * matrix[0][col] * determinant(subMatrix);
    }
    return det % 26;
}
vector<vector<int>> adjugate(const vector<vector<int>>& matrix){
    vector<vector<int>> adj(matrix.size(), vector<int>(matrix[0].size()));
    for (size_t i = 0; i < matrix.size(); ++i) {
        for (size_t j = 0; j < matrix[0].size(); ++j) {
            vector<vector<int>> subMatrix(matrix.size() - 1, vector<int>(matrix[0].size() - 1));
            for (size_t m = 0; m < matrix.size(); ++m) {
                for (size_t n = 0; n < matrix[0].size(); ++n) {
                    if (m < i && n < j) {
                        subMatrix[m][n] = matrix[m][n];
                    } else if (m < i && n > j) {
                        subMatrix[m][n - 1] = matrix[m][n];
                    } else if (m > i && n < j) {
                        subMatrix[m - 1][n] = matrix[m][n];
                    } else if (m > i && n > j) {
                        subMatrix[m - 1][n - 1] = matrix[m][n];
                    }
                }
            }
            adj[j][i] = ((i + j) % 2 == 0 ? 1 : -1) * determinant(subMatrix);
        }
    }
    return adj;
}
vector<vector<int>> inverseKeyMatrix(const vector<vector<int>>& keyMatrix){
    int det = determinant(keyMatrix);
    int detInv = modInverse(det, 26);
    if (detInv == -1) {
        return {}; // matrice inverse n'existe pas
    }
    vector<vector<int>> adj = adjugate(keyMatrix);
    vector<vector<int>> invKeyMatrix(adj.size(), vector<int>(adj.size()));
    for (size_t i = 0; i < adj.size(); ++i) {
        for (size_t j = 0; j < adj.size(); ++j) {
            invKeyMatrix[i][j] = (adj[i][j] * detInv) % 26;
            if (invKeyMatrix[i][j] < 0) {
                invKeyMatrix[i][j] += 26; // s'assurer que les éléments sont positifs
            }
        }
    }
    return invKeyMatrix;
}

string hillDecrypt(const string& text, const vector<vector<int>>& keyMatrix){
    
    vector<vector<int>> inverseKey = inverseKeyMatrix(keyMatrix); 
    if (inverseKey.empty()) {
    throw invalid_argument("La matrice n'est pas inversible modulo 26");
    }
    return hillEncrypt(text, inverseKey); // utiliser la même fonction d'encryption avec la matrice inverse pour déchiffrer
}

int main() {
    string text = "HELLO";
    vector<vector<int>> keyMatrix = {{3, 3 ,4 ,5, 6}, {2, 5 ,3 ,6,8}, {1, 4 ,5 ,7,9} ,{ 4,6,8,9,10},{5,6,7,8,9}}; // matrice clé 5x5
    string encryptedText = hillEncrypt(text, keyMatrix);
    cout << "Encrypted Text: " << encryptedText << endl;
    string decryptedText = hillDecrypt(encryptedText, keyMatrix);
    cout << "Decrypted Text: " << decryptedText << endl;
    return 0;
}