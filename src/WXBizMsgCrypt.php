<?php

namespace SakuaraBj\Wxbizmsgcrypt;

use SakuaraBj\Wxbizmsgcrypt\CallBack\ErrorCode;
use SakuaraBj\Wxbizmsgcrypt\CallBack\Prpcrypt;
use SakuaraBj\Wxbizmsgcrypt\CallBack\SHA1;
use SakuaraBj\Wxbizmsgcrypt\CallBack\XMLParse;

class WXBizMsgCrypt
{
    protected $m_sToken;
    protected $m_sEncodingAesKey;
    protected $m_sReceiveId;

    /**
     * 构造函数
     * @param string $token  开发者设置的token
     * @param string $encodingAesKey 开发者设置的EncodingAESKey
     * @param string $receiveId , 不同应用场景传不同的id
     */
    public function __construct(string $token, string $encodingAesKey, string $receiveId)
    {
        $this->m_sToken = $token;
        $this->m_sEncodingAesKey = $encodingAesKey;
        $this->m_sReceiveId = $receiveId;
    }

    /**
     * 验证URL
     * @param $sMsgSignature: 签名串，对应URL参数的msg_signature
     * @param $sTimeStamp: 时间戳，对应URL参数的timestamp
     * @param $sNonce: 随机串，对应URL参数的nonce
     * @param $sEchoStr: 随机串，对应URL参数的echostr
     * @return int | array  成功0，失败返回对应的错误码
    */
    public function VerifyURL($sMsgSignature, $sTimeStamp, $sNonce, $sEchoStr )
    {
        if (strlen($this->m_sEncodingAesKey) != 43) {
            return ErrorCode::$IllegalAesKey;
        }

        $pc = new Prpcrypt($this->m_sEncodingAesKey);

        //verify msg_signature
        $sha1 = new SHA1();

        $array = $sha1->getSHA1($this->m_sToken, $sTimeStamp, $sNonce, $sEchoStr);

        $ret = $array[0];

        if ($ret != 0) {
            return $ret;
        }

        $signature = $array[1];
        if ($signature != $sMsgSignature) {
            return ErrorCode::$ValidateSignatureError;
        }

        $result = $pc->decrypt($sEchoStr, $this->m_sReceiveId);

        if ($result[0] != 0) {
            return $result[0];
        }
        return $result[1];
    }

    /**
     * @param $sReplyMsg
     * @param $sTimeStamp
     * @param $sNonce
     * @param $sEncryptMsg
     * @return int
     */
    public function EncryptMsg($sReplyMsg, $sTimeStamp, $sNonce, &$sEncryptMsg): int
    {
        $pc = new Prpcrypt($this->m_sEncodingAesKey);

        //加密
        $array = $pc->encrypt($sReplyMsg, $this->m_sReceiveId);

        if ($array[0] != 0) {
            return $array[0];
        }

        if ($sTimeStamp == null) {
            $sTimeStamp = time();
        }

        $encrypt = $array[1];

        //生成安全签名
        $sha1 = new SHA1;
        $array = $sha1->getSHA1($this->m_sToken, $sTimeStamp, $sNonce, $encrypt);
        $ret = $array[0];
        if ($ret != 0) {
            return $ret;
        }
        $signature = $array[1];

        //生成发送的xml
        $sEncryptMsg = (new XMLParse())->generate($encrypt, $signature, $sTimeStamp, $sNonce);
        return ErrorCode::$OK;
    }

    public function DecryptMsg($sMsgSignature, $sTimeStamp, $sNonce, $sPostData, &$sMsg)
    {
        if (strlen($this->m_sEncodingAesKey) != 43) {
            return ErrorCode::$IllegalAesKey;
        }

        $pc = new Prpcrypt($this->m_sEncodingAesKey);

        //提取密文
        $array = (new XMLParse)->extract($sPostData);
        $ret = $array[0];

        if ($ret != 0) {
            return $ret;
        }

        if ($sTimeStamp == null) {
            $sTimeStamp = time();
        }

        $encrypt = $array[1];

        //验证安全签名
        $sha1 = new SHA1;
        $array = $sha1->getSHA1($this->m_sToken, $sTimeStamp, $sNonce, $encrypt);
        $ret = $array[0];

        if ($ret != 0) {
            return $ret;
        }

        $signature = $array[1];
        if ($signature != $sMsgSignature) {
            return ErrorCode::$ValidateSignatureError;
        }

        $result = $pc->decrypt($encrypt, $this->m_sReceiveId);
        if ($result[0] != 0) {
            return $result[0];
        }
        $sMsg = $result[1];

        return ErrorCode::$OK;
    }
}