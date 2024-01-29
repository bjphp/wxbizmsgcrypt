<?php

namespace SakuaraBj\Wxbizmsgcrypt\Providers;

use Illuminate\Support\ServiceProvider;
use SakuaraBj\Wxbizmsgcrypt\WXBizMsgCrypt;

class WxbizmsgcryptServiceProvider extends ServiceProvider
{
    public function boot()
    {
        $this->publishes([
            __DIR__.'/config/wxbizmsgcrypt.php' => config_path('wxbizmsgcrypt.php'),
        ], 'config');
    }

    public function register()
    {
        $this->app->singleton('wxcrypt', function() {
            return new WXBizMsgCrypt(
                config('wxbizmsgcrypt.token'),
                config('wxbizmsgcrypt.encodingAesKey'),
                config('wxbizmsgcrypt.corpId')
            );
        });
    }
}