<?php

namespace Ebrook\KeycloakWebGuard\Filament\Pages\Auth;

use Filament\Pages\SimplePage;
use Illuminate\Http\RedirectResponse;
use Illuminate\Routing\Redirector;
use Illuminate\Support\Facades\Auth;
use Ebrook\KeycloakWebGuard\Facades\KeycloakWeb;

class KeycloakLogin extends SimplePage
{
    protected string $view = 'filament-panels::pages.auth.login';

    public function mount(): RedirectResponse|Redirector|null
    {
        if (Auth::check()) {
            return redirect()->intended(filament()->getUrl());
        }

        // Store panel context in session so callback knows which guard to use
        $panel = filament()->getCurrentPanel();
        if ($panel) {
            $panelId = $panel->getId();
            session()->put('keycloak_panel_context', $panelId);
            session()->save();
        }

        $url = KeycloakWeb::getLoginUrl();
        KeycloakWeb::saveState();

        return redirect()->away($url);
    }
}
