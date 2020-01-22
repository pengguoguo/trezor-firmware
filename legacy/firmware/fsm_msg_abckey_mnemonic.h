
void fsm_msgReqMnemonic(const ReqMnemonic *msg)
{
	//uint32_t Mnemonic_Array_Index = 0;
	(void)msg;

	CHECK_PIN

	CHECK_NOT_INITIALIZED
    /* 产生助记词 */
	char mnemonic[MAX_MNEMONIC_LEN + 1];
	if (config_getMnemonic(mnemonic, sizeof(mnemonic)))
	{
		/* 等待用户确认助记词，参考了reset_backup的实现 */
		abckey_reset_backup(true,mnemonic);
	}
}
