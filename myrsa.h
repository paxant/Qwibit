#ifndef MYRSA_H
#define MYRSA_H
#define SMS_SIZE            460
#define PLAINTEXT_SIZE      (SMS_SIZE / sizeof(int))
#define CIPHERTEXT_SIZE     (SMS_SIZE)

class MyRSA
{
private:
        int publicKey[2];
        int privateKey[2];
        void encrypt(char* plainText, char* chipherText);
        void decrypt(char* cipherText, char* plainText);
        int GCD(int x, int y);
        int modinv(int a, int m);
        void GEN();
    public:
        void rsa();
        void rsa_e_d(char* host, char* giver, bool mode = false);
        void pub_key(int n, int e);
        void priv_key(int n, int d);
        void pub_key_voz(int* Key);
};

#endif // MYRSA_H
