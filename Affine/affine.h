typedef struct affine
{
    char* txtToCrypt;
    int a;
    int b;
} affine;

typedef struct affineDecryptStr
{
    char* txtToDecrypt;
    int a;
    int b;
} affineDecryptStr;

char *affineCrypt(affine* aff);
char *affineCryptOnlyAlph(affine* aff);
char *affineDecrypt(affineDecryptStr* decaff);
char *affineDecryptOnlyAlph(affineDecryptStr* decaff);
int gcd(int a, int b);
int modInv(int a, int m);