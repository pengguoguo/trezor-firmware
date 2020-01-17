/*
 * abckey_reset.h
 *
 *  Created on:
 *      Author:
 */

#ifndef LEGACY_FIRMWARE_ABCKEY_RESET_H_
#define LEGACY_FIRMWARE_ABCKEY_RESET_H_

#include <stdbool.h>
#include <stdint.h>

void abckey_reset_backup(bool separated, const char *mnemonic);

#endif /* LEGACY_FIRMWARE_ABCKEY_RESET_H_ */
