/*
 * abckey_reset.c
 *
 *  Created on:
 *      Author:
 */
#include "bip39.h"
#include "config.h"
#include "fsm.h"
#include "gettext.h"
#include "layout2.h"
#include "memzero.h"
#include "messages.h"
#include "messages.pb.h"
#include "oled.h"
#include "protect.h"
#include "rng.h"
#include "sha2.h"
#include "util.h"

#include "AccHw_config.h"
#include "AccHw_crypto.h"

#include "usb.h"

#include "messages-abckey-mnemonic.pb.h"

AccHw_RSApubKey_stt gAccHw_RSApubKey_stt;
#if 0
const uint8_t gPublicExponent_RSAEncDec[] = {
		0x01, 0x00, 0x01
};
const uint8_t gModulus_RSAEncDec[] = {
		0x5A,0xB5,0x96,0x7E,0x8A,0xE5,0xA0,0xB6,0xD5,0x84,0x35,0xB1,0xD9,0x31,0xF1,0xC5,
		0x82,0xF0,0xFC,0xBB,0x3B,0xA1,0x43,0xD6,0xD5,0x43,0x8B,0xF0,0x9C,0x36,0xBE,0x61,
		0xD4,0x6E,0x48,0xFD,0x5A,0xCB,0x5A,0x17,0x74,0x6D,0x2D,0x3B,0x47,0x04,0x42,0x1D,
		0xE5,0x9E,0x16,0x9E,0xCE,0xB4,0x0E,0x9D,0xCF,0xF6,0xEE,0x0A,0x77,0xBE,0x52,0xB0,
		0x8F,0xB2,0xF4,0xFF,0xAF,0x25,0x5A,0xA5,0xE5,0x2A,0xD6,0x75,0xDB,0xC8,0x88,0x22,
		0xD6,0x41,0x60,0x06,0xDC,0x59,0x01,0xAE,0xEE,0x88,0xBD,0xCE,0xF6,0xEB,0x04,0xD5,
		0xD7,0xF8,0xBF,0xCB,0xAB,0x80,0x36,0x75,0x2F,0x1F,0x86,0xEA,0xC5,0xF3,0x69,0x27,
		0x34,0x5A,0xEE,0xA3,0x2B,0x6D,0x31,0x21,0xFC,0xA4,0x66,0xFC,0xC1,0x02,0xEB,0x18,
		0x79,0x3D,0x98,0xB2,0xC0,0xFC,0x71,0x09,0xA0,0x3D,0xA0,0x83,0xA1,0x33,0x0B,0xDD,
		0x81,0x6F,0x0F,0x96,0xA0,0x2B,0xF2,0xDE,0x64,0x23,0xA6,0x47,0xA8,0xD5,0x0A,0x8E,
		0xD5,0xE8,0x02,0xF9,0xEB,0xD1,0xFF,0xC2,0x2C,0xFE,0xAB,0x46,0x19,0x37,0xF6,0x62,
		0xA8,0xC4,0xBE,0x5E,0x22,0x37,0x8C,0x83,0xF0,0x3B,0xF4,0xAC,0xE5,0x50,0x31,0xB0,
		0x41,0xEF,0xAC,0xFB,0x45,0xEE,0x0A,0x19,0xEE,0xA5,0x54,0x13,0x35,0xB5,0x39,0xA1,
		0xE3,0x11,0x48,0x51,0xFA,0x66,0xAE,0xDC,0xC7,0xB5,0x78,0x9C,0xC5,0xB3,0x09,0xD6,
		0x02,0xEA,0x5C,0xBA,0x9C,0xBD,0x14,0x10,0x2C,0x5B,0x14,0xEF,0x98,0x19,0x58,0xCB,
		0xC4,0x57,0xE4,0xCE,0xFF,0xB0,0xB4,0xAA,0x47,0xEF,0xBC,0x8A,0xDE,0x95,0xB8,0xD5
};
#endif
#if 0
// separated == true if called as a separate workflow via BackupMessage
void reset_backup(bool separated, const char *mnemonic) {
  if (separated) {
    bool needs_backup = false;
    config_getNeedsBackup(&needs_backup);
    if (!needs_backup) {
      fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                      _("Seed already backed up"));
      return;
    }

    config_setUnfinishedBackup(true);
    config_setNeedsBackup(false);
  }

  for (int pass = 0; pass < 2; pass++) {
    int i = 0, word_pos = 1;
    while (mnemonic[i] != 0) {
      // copy current_word
      int j = 0;
      while (mnemonic[i] != ' ' && mnemonic[i] != 0 &&
             j + 1 < (int)sizeof(current_word)) {
        current_word[j] = mnemonic[i];
        i++;
        j++;
      }
      current_word[j] = 0;
      if (mnemonic[i] != 0) {
        i++;
      }
      layoutResetWord(current_word, pass, word_pos, mnemonic[i] == 0);
      if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmWord, true)) {
        if (!separated) {
          session_clear(true);
        }
        layoutHome();
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        return;
      }
      word_pos++;
    }
  }

  config_setUnfinishedBackup(false);

  if (separated) {
    fsm_sendSuccess(_("Seed successfully backed up"));
#if (DEBUG_RTT == 1)

#endif
  } else {
    config_setNeedsBackup(false);
    if (config_setMnemonic(mnemonic)) {
      fsm_sendSuccess(_("Device successfully initialized"));
    } else {
      fsm_sendFailure(FailureType_Failure_ProcessError,
                      _("Failed to store mnemonic"));
    }
  }
  layoutHome();
}
#endif

extern uint8_t gabc_key_mod_flag;
extern uint8_t gabc_key_exp_flag;

extern uint8_t gUserpublic_Mod[];
extern uint8_t gUserpublic_Exp[];

static char current_word[10];

uint8_t            gPreallocated_buffer_RSAEncDec[4096];
AccHw_RSAinOut_stt gInOut_st;
membuf_stt         gMembuf_stt;
uint8_t            gOutput_RSAEncDec[2048/8] = {0x00};

void abckey_reset_backup(bool separated, const char *mnemonic)
{
	bool acked = false;
	if(gabc_key_mod_flag == 1 && gabc_key_exp_flag == 1){
		if(separated)
		{
			bool needs_backup = false;
			config_getNeedsBackup(&needs_backup);
			if (!needs_backup) {
				fsm_sendFailure(FailureType_Failure_UnexpectedMessage,_("Seed already backed up"));
				return;
			}
			config_setUnfinishedBackup(true);
			config_setNeedsBackup(false);
		}

		for (int pass = 0; pass < 2; pass++) {
			int i = 0, word_pos = 1;
			while (mnemonic[i] != 0) {
			  // copy current_word
			  int j = 0;
			  while (mnemonic[i] != ' ' && mnemonic[i] != 0 && j + 1 < (int)sizeof(current_word)) {
				current_word[j] = mnemonic[i];
				i++;
				j++;
			  }
			  current_word[j] = 0;
			  if (mnemonic[i] != 0) {
				i++;
			  }
			  //layoutResetWord(current_word, pass, word_pos, mnemonic[i] == 0);
			  /*1. 用客户的RAS公钥加密助记词 */

			  gMembuf_stt.mSize = sizeof(gPreallocated_buffer_RSAEncDec);
			  gMembuf_stt.mUsed = 0;
			  gMembuf_stt.pmBuf = gPreallocated_buffer_RSAEncDec;

			  /* Fill the RSAinOut_stt */
			  gInOut_st.pmInput    = (uint8_t*)current_word;
			  gInOut_st.mInputSize = strlen(current_word);
			  gInOut_st.pmOutput = gOutput_RSAEncDec;

			  gAccHw_RSApubKey_stt.mExponentSize = sizeof((char*)gUserpublic_Exp);//gPublicExponent_RSAEncDec);
			  gAccHw_RSApubKey_stt.mModulusSize  = sizeof((char*)gUserpublic_Mod);//gModulus_RSAEncDec);
			  gAccHw_RSApubKey_stt.pmExponent    = (uint8_t *)gUserpublic_Exp;//gPublicExponent_RSAEncDec;
			  gAccHw_RSApubKey_stt.pmModulus     = (uint8_t *)gUserpublic_Mod;//gModulus_RSAEncDec;

			  AccHw_RSA_PKCS1v15_Encrypt(&gAccHw_RSApubKey_stt,&gInOut_st,&gMembuf_stt);

			  usbTiny(1);

			  /*2. 发送助记词 */
			  msg_write(MessageType_MessageType_RspMnemonic,&gMembuf_stt);

			  while(1){
				  usbPoll();
				  /*3. 等待用户在PC上的确认助记词消息 */
				  /* 超时或用户取消，怎么处理? */
				  if(PCRespondType_PCRespond_ConfirmWord == msg_tiny_id){
					  msg_tiny_id = 0xFFFF;
					  acked = true;
				  }
				  if(acked){
					  usbSleep(5);
					  /* 用户确认 ，继续发送下一个助记词*/
					  break;
				  }
			  }
			  usbTiny(0);
	       }//助记词发送结束
	#if 0
			  if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmWord, true)) {
				if (!separated) {
				  session_clear(true);
				}
				layoutHome();
				fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
				return;
			  }
	#endif
			  word_pos++;
			}

		  config_setUnfinishedBackup(false);

		  if (separated) {
			fsm_sendSuccess(_("Seed successfully backed up"));
		#if (DEBUG_RTT == 1)

		#endif
		  } else {
			config_setNeedsBackup(false);
			if (config_setMnemonic(mnemonic)) {
			  fsm_sendSuccess(_("Device successfully initialized"));
			} else {
			  fsm_sendFailure(FailureType_Failure_ProcessError,
							  _("Failed to store mnemonic"));
			}
		  }
		  layoutHome();
	}//已经接收了用户的RSA公钥
	else{
	}
}
