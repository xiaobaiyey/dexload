#pragma once
void rc4_init(unsigned char *s, unsigned char *key, unsigned long Len);
void rc4_crypt(unsigned char *s, unsigned char *Data, unsigned long Len);
