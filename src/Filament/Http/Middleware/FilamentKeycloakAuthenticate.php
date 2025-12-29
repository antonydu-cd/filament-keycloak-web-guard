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
            
            // Check if user is authenticated with this guard
            if ($guard->check()) {
                $user = $guard->user();
                
                // Set tenant context and potentially switch user account for tenant switching
                $targetTenant = null;
                $targetUser = $user; // Default to current user

                // Check if URL contains tenant parameter (for tenant switching)
                $routeParams = $request->route() ? $request->route()->parameters() : [];
                if (isset($routeParams['tenant'])) {
                    $urlTenantId = $routeParams['tenant'];

                    // Validate tenant_id: must be positive integer
                    if (!is_numeric($urlTenantId) || $urlTenantId <= 0 || $urlTenantId > 999999) {
                        \Illuminate\Support\Facades\Log::warning('FilamentKeycloakAuthenticate: Invalid tenant ID format', [
                            'tenant_id' => $urlTenantId,
                            'type' => gettype($urlTenantId),
                        ]);
                    } else {
                        // Find tenant by ID from URL
                        $urlTenant = \App\Models\Tenant::find((int)$urlTenantId);
                        if ($urlTenant) {
                            // Validate user email format and length before database query
                            $userEmail = $user->email ?? '';
                            if (!filter_var($userEmail, FILTER_VALIDATE_EMAIL) || strlen($userEmail) > 254) {
                                \Illuminate\Support\Facades\Log::warning('FilamentKeycloakAuthenticate: Invalid user email format', [
                                    'email_length' => strlen($userEmail),
                                ]);
                            } else {
                                // Check if user has access to this tenant (find the user account for this tenant)
                                $tenantUser = \App\Models\Tenant\User::where('email', $userEmail)
                                    ->where('tenant_id', (int)$urlTenantId)
                                    ->first();

                                if ($tenantUser) {
                                    $targetTenant = $urlTenant;
                                    $targetUser = $tenantUser; // Switch to the user account for this tenant
                                } else {
                                    \Illuminate\Support\Facades\Log::warning('FilamentKeycloakAuthenticate: User does not have account in requested tenant', [
                                        'url_tenant_id' => $urlTenantId,
                                        'user_email_hash' => hash('sha256', $user->email ?? ''),
                                    ]);
                                }
                            }
                        }
                    }
                }

                // Fall back to user's default tenant if no URL tenant or no access
                if (!$targetTenant && method_exists($user, 'tenant') && $user->tenant) {
                    $targetTenant = $user->tenant;
                }

                if ($targetTenant) {
                    // If we're switching user accounts, update the authenticated user
                    if ($targetUser->id !== $user->id) {
                        try {
                            // Update the authenticated user in the guard
                            $guard->setUser($targetUser);
                            $this->auth->setUser($targetUser);
                        } catch (\Exception $e) {
                            // Log error but continue with original user
                            \Illuminate\Support\Facades\Log::error('FilamentKeycloakAuthenticate: Failed to switch authenticated user', [
                                'error' => $e->getMessage(),
                                'from_user_id' => $user->id,
                                'to_user_id' => $targetUser->id,
                                'tenant_id' => $targetTenant->id,
                            ]);
                            // Continue with original user
                            $targetUser = $user;
                        }
                    }

                    \Filament\Facades\Filament::setTenant($targetTenant);
                }

                $this->auth->shouldUse($guardName);
                return;
            }
            
            // If not authenticated, try to authenticate from session token
            $token = \Ebrook\KeycloakWebGuard\Facades\KeycloakWeb::retrieveToken();
            if ($token && !empty($token['access_token'])) {
                if ($guard->validate($token)) {
                    $this->auth->shouldUse($guardName);
                    return;
                }
            }
            
            // Log why authentication failed (only in non-production)
            if (!\Illuminate\Support\Facades\App::environment('production')) {
                \Illuminate\Support\Facades\Log::warning('FilamentKeycloakAuthenticate: Authentication failed', [
                    'guard_name' => $guardName,
                    'guard_check' => $guard->check(),
                    'token_exists' => !is_null($token),
                    'request_path' => $request->path(),
                ]);
            }
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
