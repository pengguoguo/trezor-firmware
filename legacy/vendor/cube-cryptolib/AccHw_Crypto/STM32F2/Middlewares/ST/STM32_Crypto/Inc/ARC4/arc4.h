/**
  ******************************************************************************
  * @file    arc4.h
  * @author  MCD Application Team
  * @version V3.0.0
  * @date    05-June-2015
  * @brief   ARC4
  ******************************************************************************
  * @attention
  *
  * <h2><center>&copy; COPYRIGHT 2015 STMicroelectronics</center></h2>
  *
  * Licensed under MCD-ST Image SW License Agreement V2, (the "License");
  * You may not use this file except in compliance with the License.
  * You may obtain a copy of the License at:
  *
  *        http://www.st.com/software_license_agreement_liberty_v2
  *
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  * See the License for the specific language governing permissions and
  * limitations under the License.
  *
  *****************************************************************************/
/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef __CRL_ARC4_H__
#define __CRL_ARC4_H__

#ifdef __cplusplus
extern "C"
{
#endif

  /** @ingroup ARC4
    * @{
    */


  /**
    * @brief  Structure describing an ARC4 context
    */
  /* Exported types ------------------------------------------------------------*/
  typedef struct
  {
    uint32_t   mContextId;  /*!< Unique ID of this AES-GCM Context. \b Not \b used in current implementation. */
    SKflags_et mFlags;      /*!< 32 bit mFlags, for future use */
    const uint8_t *pmKey;   /*!< Pointer to original Key buffer */
    int32_t   mKeySize;     /*!< ARC4 Key length in bytes. This must be set by the caller prior to calling Init */
    uint8_t   mX;           /*!< Internal members: This describe one of two index variables of the ARC4 state */
    uint8_t   mY;           /*!< Internal members: This describe one of two index variables of the ARC4 state */
    uint8_t   amState[256]; /*!< Internal members: This describe the 256 bytes State Matrix */
  }
  ARC4ctx_stt;


  /* Exported functions --------------------------------------------------------*/

  int32_t ARC4_Encrypt_Init(ARC4ctx_stt *P_pARC4ctx, \
                            const uint8_t *P_pKey,  \
                            const uint8_t *P_pIv);

  int32_t ARC4_Encrypt_Append(ARC4ctx_stt *P_pARC4ctx,       \
                              const uint8_t *P_pInputBuffer, \
                              int32_t        P_inputSize,    \
                              uint8_t       *P_pOutputBuffer, \
                              int32_t       *P_pOutputSize);

  int32_t ARC4_Encrypt_Finish(ARC4ctx_stt *P_pARC4ctx,       \
                              uint8_t       *P_pOutputBuffer, \
                              int32_t       *P_pOutputSize);

  int32_t ARC4_Decrypt_Init(ARC4ctx_stt *P_pARC4ctx, \
                            const uint8_t *P_pKey,  \
                            const uint8_t *P_pIv);

  int32_t ARC4_Decrypt_Append(ARC4ctx_stt *P_pARC4ctx,       \
                              const uint8_t *P_pInputBuffer, \
                              int32_t        P_inputSize,    \
                              uint8_t       *P_pOutputBuffer, \
                              int32_t       *P_pOutputSize);

  int32_t ARC4_Decrypt_Finish (ARC4ctx_stt *P_pARC4ctx,       \
                               uint8_t       *P_pOutputBuffer, \
                               int32_t       *P_pOutputSize);

  /** @} */

#ifdef __cplusplus
}
#endif

#endif  /*__CRL_AES_ECB_H__*/

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
