/*
 * signed_encryption_decryption.c
 *
 *
 *
 */

#ifndef ABCKEY_SIGNED_ENCRYPTION_DECRYPTION_C_
#define ABCKEY_SIGNED_ENCRYPTION_DECRYPTION_C_

#include <stdint.h>
#include "bignum.h"
#include "hasher.h"
#include "options.h"

int abckey_dete_user_pubkey(uint8_t* pUser_pubkey_array,uint8_t* pDigest);
int abckey_encry_mnemonic(uint8_t* pUser_pubkey_array,uint8_t* pMnemonic,uint8_t* pArray);

#endif /* ABCKEY_SIGNED_ENCRYPTION_DECRYPTION_C_ */
