#include <stdint.h>
#include <string.h>

#include <openssl/md5.h>
#include <openssl/des.h>

void DEStoMD5(uint8_t dest[],const uint8_t src[])
{
    int i = 0;
    DES_cblock k1 = "\x00\x88\x01\x01\xd2\x42\xa4\x4a";
    DES_cblock k2 = "\xe0\x54\xf2\xd2\x73\xda\xae\x4d";
    DES_cblock k3 = "\x42\xf2\x18\x20\xd3\x72\x04\xbf";
    DES_key_schedule ks1, ks2, ks3;
    DES_set_key(&k1,&ks1);
    DES_set_key(&k2,&ks2);
    DES_set_key(&k3,&ks3);
    for (i = 0; i < 32; i += 8)
    {
        DES_ecb3_encrypt((const_DES_cblock *)(src+i), (const_DES_cblock *)(dest+i), &ks1, &ks2, &ks3, DES_DECRYPT);
    }
    (void) MD5(dest, 32, dest);
    (void) MD5(dest, 16, dest+16);
}

