<?php

namespace Ebrook\KeycloakWebGuard\Filament\Http\Middleware;

use Filament\Facades\Filament;
use Illuminate\Auth\Middleware\Authenticate;
use Illuminate\Http\Request;

class FilamentKeycloakAuthenticate extends Authenticate
{
    protected function redirectTo(Request $request): ?string
    {
        if ($request->expectsJson()) {
            return null;
        }

        return route('keycloak.login');
    }

    protected function authenticate($request, array $guards): void
    {
        $guard = Filament::auth();

        if ($guard->check()) {
            $this->auth->shouldUse(Filament::getAuthGuard());
            return;
        }

        $this->unauthenticated($request, $guards);
    }
}
