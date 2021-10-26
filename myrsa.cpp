#include "myrsa.h"
#include <random>
std::random_device rd;
std::mt19937 mersenne(rd());
int pr_ch[42] = { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181 };

void MyRSA::encrypt(char* plainText, char* cipherText)
{
    long m = 1;
    int n = publicKey[0];
    int e = publicKey[1];
    int ctr = 0;
    for (int i = 0; i < PLAINTEXT_SIZE; i++) {
        for (int j = 0; j < e; j++) {
            m = (m * plainText[i]) % n;
        }
        ctr = i * sizeof(int);
        cipherText[ctr] = (char)(m & 0x00ff);
        cipherText[ctr + 1] = (char)((m & 0xff00) >> 8);
        m = 1;
    }
}
void MyRSA::decrypt(char* cipherText, char* plainText) // Принимаемое потом возвращаемое
{
    long M = 1;
    int n = privateKey[0];
    int d = privateKey[1];
    int temp = 0;
    int ctr = 0;
    for (int i = 0; i < PLAINTEXT_SIZE; i++) {
        ctr = i * sizeof(int);
        temp = (((unsigned char)cipherText[ctr + 1] << 8) | (unsigned char)cipherText[ctr]);
        for (int j = 0; j < d; j++) {
            M = (M * temp) % n;
        }
        plainText[i] = (unsigned char)(M & 0xFF);
        M = 1;
    }
}
int MyRSA::GCD(int x, int y)
{
    while (1)
    {
        if (y == 0) return x;
        x = x % y;
        if (x == 0) return y;
        y = y % x;
    }
}
int MyRSA::modinv(int a, int m)
{
    int b = m;
    int c = a;
    int i = 0;
    int j = 1;

    int x, y;

    while (c != 0)
    {
        x = b / c;
        y = b % c;
        b = c;
        c = y;
        y = j;
        j = i - j * x;
        i = y;
    }
    if (i < 0) i += m;
    return i;
}
void MyRSA::GEN()
{
    int numb_p = mersenne() % +42;
    int numb_q = mersenne() % +42;
    int p = pr_ch[numb_p];
    int q = pr_ch[numb_q];
    int n = p * q;
    int f = (p - 1) * (q - 1);
    int e = 2;
    do
    {
        e++;
    } while (GCD(e, f) != 1);
    int d = modinv(e, f);
    publicKey[0] = n;
    publicKey[1] = e;
    privateKey[0] = n;
    privateKey[1] = d;
}
void MyRSA::pub_key(int n, int e)
{
    publicKey[0] = n;
    publicKey[1] = e;
}
void MyRSA::priv_key(int n, int d)
{
    privateKey[0] = n;
    privateKey[1] = d;
}
void MyRSA::pub_key_voz(int* Key)
{
    Key[0] = publicKey[0];
    Key[1] = publicKey[1];
}
void MyRSA::rsa()
{
    GEN();
}
void MyRSA::rsa_e_d(char* host, char* giver, bool mode) // 0 - encript, 1 - decr
    {
        if (mode == false)
        {
            encrypt(host, giver);
        }
        if (mode == true)
        {
            decrypt(host, giver);
        }
    }
