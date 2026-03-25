#include <string>
#include <vector>
using namespace std;
vector<vector<int>> generateKeyMatrix(const string& key, int size);
string hillEncrypt(const string& plaintext, const vector<vector<int>>& keyMatrix);
string hillDecrypt(const string& ciphertext, const vector<vector<int>>& keyMatrix);
int modInverse(int a, int m);
int determinant(const vector<vector<int>>& matrix);
vector<vector<int>> adjugate(const vector<vector<int>>& matrix);
vector<vector<int>> inverseKeyMatrix(const vector<vector<int>>& keyMatrix);
