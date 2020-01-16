/*
 * signed_encryption_decryption.c
 *
 *
 *
 */
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "address.h"
#include "base58.h"
#include "bignum.h"
#include "ecdsa.h"
#include "hmac.h"
#include "memzero.h"
#include "rand.h"
#include "rfc6979.h"
#include "secp256k1.h"

#include "ecdsa.h"

#include "AccHw_rsa_pkcs1v15.h"

extern const uint8_t * const pubkey;
//static uint8_t user_pubkey[65] = {0x00};

int abckey_dete_user_pubkey(uint8_t* pUser_pubkey_array,uint8_t* pDigest)
{
	int Result = 0;
	uint8_t hash[32] = {0};
	for(int i = 0;i < 5;i++)
	{
		/* 遍历abckey公钥 */
		/* 计算签名 */
		/* 与数字签名比较  */
		sha256_Raw(pUser_pubkey_array,64,hash);
		if(0 != ecdsa_verify_digest(&secp256k1,pubkey[i],pDigest,hash))
		{
			memset(hash,0,32);
			Result = 1;
		}
		else
		{
			Result = 0;
		}
	}
	return Result;
}

int abckey_encry_mnemonic(uint8_t* pUser_pubkey_array,uint8_t* pMnemonic,uint8_t* pArray)
{
	int Result = 0;

	//AccHw_RSA_PKCS1v15_Encrypt();
	return Result;
}
