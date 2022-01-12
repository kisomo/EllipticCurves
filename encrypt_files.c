
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/evp.h>


//sudo apt-get install libssl-dev
// gcc -g encrypt_files.c -o encrypto_files -lcrypto -lssl 
// ./encrypt_files test_file.txt

//https://stackoverflow.com/questions/2262386/generate-sha256-with-openssl-and-c/10632725


void sha256_hash_string (unsigned char hash[SHA256_DIGEST_LENGTH], char outputBuffer[65])
{
    int i = 0;
    for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
    { sprintf(outputBuffer + (i * 2), "%02x", hash[i]);}
    outputBuffer[64] = 0;
}

void sha256_string(char *string, char outputBuffer[65])
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, strlen(string));
    SHA256_Final(hash, &sha256);
    int i = 0;
    for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
    { sprintf(outputBuffer + (i * 2), "%02x", hash[i]); }
    outputBuffer[64] = 0;
}

int sha256_file(char *path, char outputBuffer[65])
{
    FILE *file = fopen(path, "rb");
    if(!file) {return -534;}

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    const int bufSize = 32768;
    unsigned char *buffer = malloc(bufSize);
    int bytesRead = 0;
    if(!buffer) {return ENOMEM;}
    while((bytesRead = fread(buffer, 1, bufSize, file)))
    { SHA256_Update(&sha256, buffer, bytesRead); }
    SHA256_Final(hash, &sha256);

    sha256_hash_string(hash, outputBuffer);
    fclose(file);
    free(buffer);
    return 0;
}

int main(int argc, char **argv)
{
   // hash a sentence
   char *string = "I love C"; char outputBuffer1[65];
   printf("sentence = %s\n", string);
   printf("hashed string is before = %s\n", outputBuffer1);
   sha256_string(string, outputBuffer1);
   printf("hashed string is = %s\n\n", outputBuffer1);

   //hash a file
   char outputBuffer2[65];
   sha256_file(argv[1], outputBuffer2);
   printf("hashed file is = %s\n\n", outputBuffer2);

   printf("========= method 2 ============\n");

   ////https://stackoverflow.com/questions/60984946/how-to-hash-the-contents-of-a-file-in-c
   unsigned char sha256_digest[SHA256_DIGEST_LENGTH];
   unsigned char md5_digest[MD5_DIGEST_LENGTH];
   unsigned char *buffer = "Hello World!";
   int i;

   SHA256(buffer, strlen(buffer), sha256_digest);
   MD5(buffer, strlen(buffer), md5_digest);
   for (i = 0; i < SHA256_DIGEST_LENGTH; i++) 
   { printf("%02x", sha256_digest[i]); } printf("\n");
   for (i = 0; i < MD5_DIGEST_LENGTH; i++) 
   { printf("%02x", md5_digest[i]); } printf("\n");

   printf("============== method 3 ======================\n");
   //https://home.uncg.edu/cmp/faculty/srtate/580.s13/digest_ex.php
   //typedef unsigned char byte;
   EVP_MD_CTX *ctx;
   ctx = EVP_MD_CTX_new();
   if (ctx == NULL){return -1;}
   const int DataLen = 30;
   unsigned int outLen;

   //byte digest[EVP_MAX_MD_SIZE];
   //int i;
   //byte* testdata = (byte *)malloc(DataLen);
   //for (i=0; i<DataLen; i++) {testdata[i] = 6;}
   char *testdata = "I need hedge fund job";
   char digest[EVP_MAX_MD_SIZE];

   EVP_DigestInit(ctx, EVP_sha256());
   EVP_DigestUpdate(ctx, testdata, DataLen);
   EVP_DigestFinal(ctx, digest, &outLen);

   for (i=0; i<outLen; i++)
	{printf("%02x", digest[i]);}
   putchar('\n');
   EVP_MD_CTX_free(ctx);


   return 0;
}




//https://gist.github.com/arrieta/7d2e196c40514d8b5e9031f2535064fc














