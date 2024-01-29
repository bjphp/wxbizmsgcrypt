<?php

namespace SakuaraBj\Wxbizmsgcrypt\CallBack;

class PKCS7Encoder
{
    public static $block_size = 32;

    /**
     * @param $text
     * @return string 补齐明文字符串
     */
    function encode($text)
    {
        $text_length = strlen($text);
            //计算需要填充的位数
        $amount_to_pad = self::$block_size - ($text_length % self::$block_size);
        if ($amount_to_pad == 0) {
            $amount_to_pad = self::$block_size;
        }
        //获得补位所用的字符
        $pad_chr = chr($amount_to_pad);
        $tmp = str_repeat($pad_chr, $amount_to_pad);
        return $text . $tmp;
    }

    /**
     * 对解密后的明文进行补位删除
     * @param $text
     * @return string
     */
    function decode($text)
    {
        $pad = ord(substr($text, -1));
        if ($pad < 1 || $pad > self::$block_size) {
            $pad = 0;
        }
        return substr($text, 0, (strlen($text) - $pad));
    }
}