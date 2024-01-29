<?php

namespace SakuaraBj\Wxbizmsgcrypt\CallBack;

/**
 * -40001: 签名验证错误
 * -40002: xml解析失败
 * -40003: sha加密生成签名失败
 * -40004: encodingAesKey 非法
 * -40005: corpid 校验错误
 * -40006: aes 加密失败
 * -40007: aes 解密失败
 * -40008: 解密后得到的buffer非法
 * -40009: base64加密失败
 * -40010: base64解密失败
 * -40011: 生成xml失败
 */
class ErrorCode
{
    public static $OK = 0;
    public static $ValidateSignatureError = -40001;
    public static $ParseXmlError = -40002;
    public static $ComputeSignatureError = -40003;
    public static $IllegalAesKey = -40004;
    public static $ValidateCorpidError = -40005;
    public static $EncryptAESError = -40006;
    public static $DecryptAESError = -40007;
    public static $IllegalBuffer = -40008;
    public static $EncodeBase64Error = -40009;
    public static $DecodeBase64Error = -40010;
    public static $GenReturnXmlError = -40011;
}