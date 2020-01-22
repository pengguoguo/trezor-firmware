/*
 * abckey_pulickey_process.c
 *
 *  Created on:
 *      Author:
 */
#include "sha2.h"
#include "ecdsa.h"
#include "string.h"

#include "secp256k1.h"
#include "messages-abckey-pubkey.pb.h"

//extern const uint8_t * const pubkey[];

const uint8_t * const pubkey[5] = {
	(const uint8_t *)"\x04\xd5\x71\xb7\xf1\x48\xc5\xe4\x23\x2c\x38\x14\xf7\x77\xd8\xfa\xea\xf1\xa8\x42\x16\xc7\x8d\x56\x9b\x71\x04\x1f\xfc\x76\x8a\x5b\x2d\x81\x0f\xc3\xbb\x13\x4d\xd0\x26\xb5\x7e\x65\x00\x52\x75\xae\xde\xf4\x3e\x15\x5f\x48\xfc\x11\xa3\x2e\xc7\x90\xa9\x33\x12\xbd\x58",
	(const uint8_t *)"\x04\x63\x27\x9c\x0c\x08\x66\xe5\x0c\x05\xc7\x99\xd3\x2b\xd6\xba\xb0\x18\x8b\x6d\xe0\x65\x36\xd1\x10\x9d\x2e\xd9\xce\x76\xcb\x33\x5c\x49\x0e\x55\xae\xe1\x0c\xc9\x01\x21\x51\x32\xe8\x53\x09\x7d\x54\x32\xed\xa0\x6b\x79\x20\x73\xbd\x77\x40\xc9\x4c\xe4\x51\x6c\xb1",
	(const uint8_t *)"\x04\x43\xae\xdb\xb6\xf7\xe7\x1c\x56\x3f\x8e\xd2\xef\x64\xec\x99\x81\x48\x25\x19\xe7\xef\x4f\x4a\xa9\x8b\x27\x85\x4e\x8c\x49\x12\x6d\x49\x56\xd3\x00\xab\x45\xfd\xc3\x4c\xd2\x6b\xc8\x71\x0d\xe0\xa3\x1d\xbd\xf6\xde\x74\x35\xfd\x0b\x49\x2b\xe7\x0a\xc7\x5f\xde\x58",
	(const uint8_t *)"\x04\x87\x7c\x39\xfd\x7c\x62\x23\x7e\x03\x82\x35\xe9\xc0\x75\xda\xb2\x61\x63\x0f\x78\xee\xb8\xed\xb9\x24\x87\x15\x9f\xff\xed\xfd\xf6\x04\x6c\x6f\x8b\x88\x1f\xa4\x07\xc4\xa4\xce\x6c\x28\xde\x0b\x19\xc1\xf4\xe2\x9f\x1f\xcb\xc5\xa5\x8f\xfd\x14\x32\xa3\xe0\x93\x8a",
	(const uint8_t *)"\x04\x73\x84\xc5\x1a\xe8\x1a\xdd\x0a\x52\x3a\xdb\xb1\x86\xc9\x1b\x90\x6f\xfb\x64\xc2\xc7\x65\x80\x2b\xf2\x6d\xbd\x13\xbd\xf1\x2c\x31\x9e\x80\xc2\x21\x3a\x13\x6c\x8e\xe0\x3d\x78\x74\xfd\x22\xb7\x0d\x68\xe7\xde\xe4\x69\xde\xcf\xbb\xb5\x10\xee\x9a\x46\x0c\xda\x45",
};

uint8_t gUserpublic_Mod[3] = {0x00};
uint8_t gHashArray[32]     = {0x00};
uint8_t gUserpublic_Exp[256]  = {0x00};

static void compute_Mod_fingerprint(uint8_t *msg, uint8_t hash[32]);

void compute_Mod_fingerprint(uint8_t *msg, uint8_t hash[32])
{
	uint8_t copy[256] = {0};
	memcpy(copy,msg,3);
    sha256_Raw(copy, 3, hash);
}


void abckey_public_save_Mod(const TxPublicKeyMod *msg)
{
	memcpy(gUserpublic_Mod,(uint8_t*)msg,3);
}

void abckey_public_signatures(uint8_t* pArray)
{
	uint8_t hash[32] = {0};
	compute_Mod_fingerprint(pArray,hash);
	memcpy(gHashArray,hash,sizeof(hash));
}

int abckey_public_verify_digest(uint8_t *msg)
{
	uint8_t verify_Array[32] = {0x00};
	int result = 0;

	memcpy(verify_Array,(uint8_t*)msg,32);

	for(int i = 0;i < 5;i++)
	{
		result = ecdsa_verify_digest(&secp256k1,pubkey[i],verify_Array, gHashArray);
		if(result == 0)
		{
			break;
		}
	}
	memset(gHashArray,0x00,32);
	return result;
}

void abckey_public_save_Exp(TxPublicKeyExp *msg)
{
	memcpy(gUserpublic_Exp,(uint8_t*)msg,256);
}

