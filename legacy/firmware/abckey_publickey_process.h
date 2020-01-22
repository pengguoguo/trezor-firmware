/*
 * abckey_publickey_process.h
 *
 *  Created on:
 *      Author:
 */

#ifndef LEGACY_FIRMWARE_ABCKEY_PUBLICKEY_PROCESS_H_
#define LEGACY_FIRMWARE_ABCKEY_PUBLICKEY_PROCESS_H_

#include "messages-abckey-pubkey.pb.h"

void abckey_public_save_Mod(const TxPublicKeyMod *msg);
void abckey_public_signatures(uint8_t* pArray);
int  abckey_public_verify_digest(uint8_t* msg);
void abckey_public_save_Exp(const TxPublicKeyExp *msg);
#endif /* LEGACY_FIRMWARE_ABCKEY_PUBLICKEY_PROCESS_H_ */
