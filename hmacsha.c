#include <openssl/ossl_typ.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> 
#include <unistd.h>
#include <stdint.h>

#define IPAD 0x36
#define OPAD 0x5C

#define SHA1_DIGESTLENGTH 20
#define SHA1_BLOCK_LENGTH 64


#define SAMPLE_MSG1 "Sample message for keylen=blocklen"
#define KEYLEN1 64

#define SAMPLE_MSG2 "Sample message for keylen<blocklen"
#define KEYLEN2 20

#define SAMPLE_MSG3 "Sample message for keylen=blocklen"
#define KEYLEN3 100

/*
 * generate a hmac sha1 signature using the given key and message 
 *
 * key := the key to sign the message
 * key_len := the length of the key in bytes 
 * msg := the message to be signed
 * msg_len := the length of the message in bytes
 * hash_out := the hash will be written to this buffer - buffer of at least SHA1_DIGESTLENGTH bytes
 * returns 0 if a hash has been generated, -1 in case of error
 */
int hmacsha1(unsigned char *key, int key_len, unsigned char *msg, int msg_len, unsigned char *hash_out )
{
   EVP_MD_CTX *mdctx;
   const EVP_MD *md;
   unsigned char md_value[EVP_MAX_MD_SIZE];
   unsigned int md_len;

   unsigned char algKey[SHA1_BLOCK_LENGTH];
   unsigned char work_key[SHA1_BLOCK_LENGTH];
   unsigned int i,work_bufLen,work_klen;
   unsigned char *work_buffer;

   md = EVP_get_digestbyname("sha1");
   if(!md) goto err_digest;
   mdctx = EVP_MD_CTX_new();
   if (mdctx == NULL) goto err_cryptcontext;

   work_bufLen = msg_len+SHA1_BLOCK_LENGTH;
   work_buffer = malloc(work_bufLen);
   if (!work_buffer) goto err_nomem1;

   // if input key size is > SHA1_BLOCK_LENGTH, we must create SHA1 of input key and
   // use the input key hash as key.
   if (key_len > SHA1_BLOCK_LENGTH)
   {
      EVP_MD_CTX_init(mdctx);
      EVP_DigestInit_ex(mdctx, md, NULL);
      
      EVP_DigestUpdate(mdctx, key, key_len);
      EVP_DigestFinal_ex(mdctx, md_value, &md_len);

      memset(work_key, 0, SHA1_BLOCK_LENGTH);
      memcpy(work_key, md_value, md_len);
      work_klen=SHA1_DIGESTLENGTH;
   }
   else
   {
      memset(work_key, 0, SHA1_BLOCK_LENGTH);
      memcpy(work_key, key, key_len);
      work_klen = key_len; 
   }
   // copy work_key to buffer which has the same size as SHA1 Block length 
   memcpy(algKey, work_key, SHA1_BLOCK_LENGTH);
   
   // put key into work buffer and append msg
   memcpy(work_buffer,algKey,SHA1_BLOCK_LENGTH);
   memcpy(work_buffer+SHA1_BLOCK_LENGTH,msg,msg_len);
   
   // XOR key with inner pad
   for (i = 0; i < SHA1_BLOCK_LENGTH; i++) *(work_buffer+i) ^= IPAD; 
   
   EVP_MD_CTX_init(mdctx);
   EVP_DigestInit_ex(mdctx, md, NULL);
   // calculate SHA1 hash for (key^IPAD)+msg - this completes step #1
   EVP_DigestUpdate(mdctx, work_buffer, work_bufLen);
   EVP_DigestFinal_ex(mdctx, md_value, &md_len);

   // put key into work buffer and append hash from step #1
   memset(algKey, 0, SHA1_BLOCK_LENGTH);
   memcpy(algKey, work_key, work_klen);
   memcpy(work_buffer, algKey, SHA1_BLOCK_LENGTH);
   memcpy(work_buffer+SHA1_BLOCK_LENGTH, md_value,md_len); 
   work_bufLen = SHA1_BLOCK_LENGTH+md_len;
   // XOR key with outer pad
   for (i = 0; i < SHA1_BLOCK_LENGTH; i++) *(work_buffer+i) ^= OPAD; 

   EVP_MD_CTX_init(mdctx);
   EVP_DigestInit_ex(mdctx, md, NULL);
   // calculate SHA1 hash for (key^opad)+H((key^IPAD)+msg) - this completes step #2
   EVP_DigestUpdate(mdctx, work_buffer, work_bufLen);
   EVP_DigestFinal_ex(mdctx, md_value, &md_len);
   EVP_MD_CTX_free(mdctx);
   free(work_buffer);
   
   if (hash_out)
      memcpy(hash_out,md_value,md_len); 
   else
      goto err_outptr;

   return 0;
   
err_nomem1: 
err_cryptcontext:
   EVP_MD_CTX_free(mdctx);
err_digest:
err_outptr:
    return -1;
}

/*
 * print the hash bytes as hexadecial
 *
 * hash := pointer to the hash bytes
 * hash_len := length of the hash in bytes
 */

void printHash(unsigned char *hash, int hash_len)
{
   int i;
   for (i=0;i<hash_len;i++) 
      printf("%02x",*(hash+i)); 
   printf("\n");
}

/*
 * compare two hashes 
 *
 * hash1 := pointer to the first hash bytes
 * hast2 := pointer to the second hash bytes
 * hash_len := length of the hash in bytes
 */

int compareHash(unsigned char *hash1, unsigned char *hash2, int hash_len)
{
   int i=0;
   while(i<hash_len && *(hash1+i)== *(hash2+i)) i++; 
   return(i == hash_len);
}

int main(int argc, char* argv[])
{
   unsigned char hash_out[SHA1_DIGESTLENGTH];
   unsigned char sample_key1[KEYLEN1];
   unsigned char sample_key2[KEYLEN2];
   unsigned char sample_key3[KEYLEN3];
   
   unsigned char expected1[SHA1_DIGESTLENGTH]={0x5F,0xD5,0x96,0xEE,0x78,0xD5,0x55,0x3C,0x8F,0xF4,0xE7,0x2D,0x26,0x6D,0xFD,0x19,0x23,0x66,0xDA,0x29};
   unsigned char expected2[SHA1_DIGESTLENGTH]={0x4C,0x99,0xFF,0x0C,0xB1,0xB3,0x1B,0xD3,0x3F,0x84,0x31,0xDB,0xAF,0x4D,0x17,0xFC,0xD3,0x56,0xA8,0x07};
   unsigned char expected3[SHA1_DIGESTLENGTH]={0x2D,0x51,0xB2,0xF7,0x75,0x0E,0x41,0x05,0x84,0x66,0x2E,0x38,0xF1,0x33,0x43,0x5F,0x4C,0x4F,0xD4,0x2A};
   int i;

   OpenSSL_add_all_digests();
   
   // fill the sample_keys
   // we test the cases: key shorter than block_len, equal block_len, longer than block_len
   for (i=0;i<KEYLEN1;i++) sample_key1[i]=i;
   for (i=0;i<KEYLEN2;i++) sample_key2[i]=i;
   for (i=0;i<KEYLEN3;i++) sample_key3[i]=i;
   
   hmacsha1(&sample_key1[0], sizeof(sample_key1), SAMPLE_MSG1,strlen(SAMPLE_MSG1), &hash_out[0] );
   printHash(&hash_out[0],SHA1_DIGESTLENGTH);
   printf("Test 1 - result like expected? %d\n",compareHash(&hash_out[0],expected1,SHA1_DIGESTLENGTH));

   hmacsha1(&sample_key2[0], sizeof(sample_key2), SAMPLE_MSG2,strlen(SAMPLE_MSG2), &hash_out[0] );
   printHash(&hash_out[0],SHA1_DIGESTLENGTH);
   printf("Test 2 - result like expected? %d\n",compareHash(&hash_out[0],expected2,SHA1_DIGESTLENGTH));
   
   hmacsha1(&sample_key3[0], sizeof(sample_key3), SAMPLE_MSG3,strlen(SAMPLE_MSG3), &hash_out[0] );
   printHash(&hash_out[0],SHA1_DIGESTLENGTH);
   printf("Test 3 - result like expected? %d\n",compareHash(&hash_out[0],expected3,SHA1_DIGESTLENGTH));
}