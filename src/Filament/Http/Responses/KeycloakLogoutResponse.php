<?php

namespace Ebrook\KeycloakWebGuard\Filament\Http\Responses;

use Filament\Auth\Http\Responses\Contracts\LogoutResponse;
use Ebrook\KeycloakWebGuard\Facades\KeycloakWeb;

class KeycloakLogoutResponse implements LogoutResponse
{
    public function toResponse($request)
    {
        $url = KeycloakWeb::getLogoutUrl();
        KeycloakWeb::forgetToken();

        return redirect()->away($url);
    }
}
