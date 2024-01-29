<?php

namespace SakuaraBj\Wxbizmsgcrypt\Test;

use PHPUnit\Framework\TestCase;
use SakuaraBj\Wxbizmsgcrypt\WXBizMsgCrypt;

class VerifyURLTest extends TestCase
{
    protected $encodingAesKey = "";
    protected $token = "";
    protected $corpId = "";

    public function testVerifyURL()
    {
        $sVerifyMsgSig = "";
        $sVerifyTimeStamp = "";
        $sVerifyNonce = "";
        $sVerifyEchoStr = "";

        $wxcpt = new WXBizMsgCrypt($this->token, $this->encodingAesKey, $this->corpId);

        // 需要返回的明文
        $sEchoStr = "";

        $errCode = $wxcpt->VerifyURL($sVerifyMsgSig, $sVerifyTimeStamp, $sVerifyNonce, $sVerifyEchoStr, $sEchoStr);

        if ($errCode == 0) {
            var_dump($sEchoStr);
            // HttpUtils.SetResponce($sEchoStr);
        } else {
            print("ERR: " . $errCode . "\n\n");
        }
    }
}