
void fsm_msgTxPublicKeyMod(const TxPublicKeyMod *msg)
{
	//RESP_ABCKEY_INIT(TxPublicKeyMod)
	CHECK_PIN
	CHECK_NOT_INITIALIZED
	/*1. 从消息中取出公钥的模数据，保存模数据*/
	abckey_public_save_Mod(msg);
	/*2. 计算签名 */
    abckey_public_signatures((uint8_t*)msg);
	/*3. 请求签名*/
    msg_write(MessageType_MessageType_RspTxPublicKeyMod,_("Req Mod'Signed"));
}

void fsm_msgTxPublicKeyModSign(const TxPublicKeyModSign *msg)
{
	int verify_result = 0;
	//RESP_ABCKEY_INIT(TxPublicKeyModSign)
	CHECK_PIN
	CHECK_NOT_INITIALIZED
    /* 得到的签名与计算的签名作对比 */
	verify_result = abckey_public_verify_digest((uint8_t*)msg);

	if(verify_result == 0){
		/* 正确，发送请求指数数据 */
		msg_write(MessageType_MessageType_TxPublicKeyModSign,_("Verify OK"));
		gabc_key_mod_flag = 1;
	}else{
		/* 错误，发送错误信息 */
		msg_write(MessageType_MessageType_TxPublicKeyModSign,_("Verify ERROR"));
	}
}

void fsm_msgTxPublicKeyExp(const TxPublicKeyExp *msg)
{
	//RESP_ABCKEY_INIT(TxPublicKeyExp)
	CHECK_PIN
	CHECK_NOT_INITIALIZED
    /*保存指数数据*/
	abckey_public_save_Exp(msg);
	/*计算指数数据的签名*/
	abckey_public_signatures((uint8_t*)msg);
	/*请求指数的签名数据*/
	msg_write(MessageType_MessageType_RspTxPublicKeyExp,_("Req Exp'Signed"));
}

void fsm_msgTxPublicKeyExpSign(const TxPublicKeyExpSign *msg)
{
	int verify_result = 0;
	//RESP_ABCKEY_INIT(TxPublicKeyExpSign)
	CHECK_PIN
	CHECK_NOT_INITIALIZED
    /*比较签名数据*/
    verify_result =  abckey_public_verify_digest((uint8_t*)msg);
	if(verify_result == 0){
		/*正确，发送成功，做标记供加密判断，可以使用*/
		msg_write(MessageType_MessageType_RspTxPublicKeyExpSign,_("Verify OK"));
		gabc_key_exp_flag = 1;
	}else{
	/*错误，发送失败*/
		msg_write(MessageType_MessageType_RspTxPublicKeyExpSign,_("Verify ERROR"));
	}
}
