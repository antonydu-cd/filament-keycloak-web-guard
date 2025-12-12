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

        // Get the panel to determine the correct login route
        $panel = Filament::getCurrentPanel();
        if (!$panel) {
            $path = $request->path();
            if (str_starts_with($path, 'app/')) {
                $panel = Filament::getPanel('app');
            }
        }
        
        if ($panel) {
            // Return the panel's login URL
            return $panel->getLoginUrl();
        }

        return route('keycloak.login');
    }

    protected function authenticate($request, array $guards): void
    {
        // Get the panel from the request
        $panel = Filament::getCurrentPanel();
        
        if (!$panel) {
            // Try to identify panel from route path
            $path = $request->path();
            if (str_starts_with($path, 'app/')) {
                $panel = Filament::getPanel('app');
            }
        }
        
        if ($panel) {
            // Set current panel context (important for Filament to work correctly)
            Filament::setCurrentPanel($panel);
            
            // Get the auth guard name for this panel
            $guardName = $panel->getAuthGuard();
            
            // Use Auth facade with the specific guard name
            $guard = \Illuminate\Support\Facades\Auth::guard($guardName);
            
            // Log for debugging
            \Illuminate\Support\Facades\Log::debug('FilamentKeycloakAuthenticate: Checking authentication', [
                'panel_id' => $panel->getId(),
                'guard_name' => $guardName,
                'guard_class' => get_class($guard),
                'is_authenticated' => $guard->check(),
                'user' => $guard->user() ? get_class($guard->user()) : null,
                'request_path' => $request->path(),
                'session_id' => session()->getId(),
                'token_in_session' => !is_null(\Ebrook\KeycloakWebGuard\Facades\KeycloakWeb::retrieveToken()),
            ]);
            
            // Check if user is authenticated with this guard
            if ($guard->check()) {
                $user = $guard->user();
                \Illuminate\Support\Facades\Log::debug('FilamentKeycloakAuthenticate: User authenticated successfully', [
                    'user_class' => get_class($user),
                    'user_email' => $user->email ?? null,
                ]);
                $this->auth->shouldUse($guardName);
                return;
            }
            
            // If not authenticated, try to authenticate from session token
            // This handles the case where token is in session but guard hasn't loaded it yet
            $token = \Ebrook\KeycloakWebGuard\Facades\KeycloakWeb::retrieveToken();
            if ($token && !empty($token['access_token'])) {
                \Illuminate\Support\Facades\Log::debug('FilamentKeycloakAuthenticate: Attempting to authenticate from session token');
                if ($guard->validate($token)) {
                    $this->auth->shouldUse($guardName);
                    return;
                }
            }
            
            // Log why authentication failed
            \Illuminate\Support\Facades\Log::warning('FilamentKeycloakAuthenticate: Authentication failed', [
                'guard_name' => $guardName,
                'guard_check' => $guard->check(),
                'token_exists' => !is_null($token),
                'request_path' => $request->path(),
            ]);
        }
        
        // Fallback: try default Filament auth
        $guard = Filament::auth();
        if ($guard && $guard->check()) {
            $this->auth->shouldUse(Filament::getAuthGuard());
            return;
        }

        $this->unauthenticated($request, $guards);
    }
}
