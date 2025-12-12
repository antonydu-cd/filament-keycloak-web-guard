<?php

namespace Ebrook\KeycloakWebGuard\Controllers;

use Illuminate\Auth\Events\Logout;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\DB;
use Ebrook\KeycloakWebGuard\Exceptions\KeycloakCallbackException;
use Ebrook\KeycloakWebGuard\Facades\KeycloakWeb;

class AuthController extends Controller
{
    /**
     * Redirect to login
     *
     * @return RedirectResponse
     */
    public function login()
    {
        // Ensure session is started before generating login URL
        if (!session()->isStarted()) {
            session()->start();
        }
        
        $url = KeycloakWeb::getLoginUrl();
        KeycloakWeb::saveState();
        
        // Log for debugging
        Log::debug('Keycloak login initiated', [
            'session_id' => session()->getId(),
            'session_state' => session()->get('_keycloak_state'),
            'login_url' => $url,
        ]);

        return redirect($url);
    }

    /**
     * Redirect to logout
     *
     * @return RedirectResponse
     */
    public function logout()
    {
        $url = KeycloakWeb::getLogoutUrl();
        KeycloakWeb::forgetToken();
      
        event(new Logout(Auth::getDefaultDriver(), Auth()->user()));
      
        return redirect($url);
    }

    /**
     * Redirect to register
     *
     * @return RedirectResponse
     */
    public function register()
    {
        $url = KeycloakWeb::getRegisterUrl();
        return redirect($url);
    }

    /**
     * Keycloak callback page
     *
     * @throws KeycloakCallbackException
     *
     * @return RedirectResponse
     */
    public function callback(Request $request)
    {
        // Ensure session is started before processing callback
        // This is critical for multi-tenant applications where session might not be initialized
        if (!session()->isStarted()) {
            session()->start();
        }
        
        // Early return if this is a redirect without parameters (likely from a previous failed attempt)
        // This prevents infinite loops when an exception is caught and redirected
        if (empty($request->all()) && empty($request->getQueryString())) {
            Log::warning('Keycloak callback: Received callback without parameters, aborting to prevent loop', [
                'full_url' => $request->fullUrl(),
                'session_id' => session()->getId(),
            ]);
            
            // Don't redirect to login again - this causes infinite loops
            // Instead, redirect to a safe page or return an error
            KeycloakWeb::forgetState();
            
            // Return a simple error response instead of redirecting
            abort(400, 'Invalid callback request. Please try logging in again.');
        }
        
        // Check for errors from Keycloak
        if (! empty($request->input('error'))) {
            $error = $request->input('error_description');
            $error = ($error) ?: $request->input('error');

            KeycloakWeb::forgetState();
            throw new KeycloakCallbackException($error);
        }

        // Check given state to mitigate CSRF attack
        $state = $request->input('state');
        
        // Log for debugging
        Log::debug('Keycloak callback state check', [
            'request_state' => $state,
            'session_id' => session()->getId(),
            'session_state' => session()->get('_keycloak_state'),
            'session_started' => session()->isStarted(),
            'request_path' => $request->path(),
            'request_url' => $request->fullUrl(),
            'all_params' => $request->all(),
            'cookie_header' => $request->header('Cookie'),
        ]);
        
        if (empty($state)) {
            Log::error('Keycloak callback: No state parameter in request', [
                'request_all' => $request->all(),
                'query_string' => $request->getQueryString(),
            ]);
            
            KeycloakWeb::forgetState();
            throw new KeycloakCallbackException('Invalid state: No state parameter received');
        }
        
        if (! KeycloakWeb::validateState($state)) {
            Log::error('Keycloak callback: State validation failed', [
                'request_state' => $state,
                'session_id' => session()->getId(),
                'session_state' => session()->get('_keycloak_state'),
                'session_started' => session()->isStarted(),
                'session_all' => session()->all(),
            ]);
            
            KeycloakWeb::forgetState();

            throw new KeycloakCallbackException('Invalid state: State mismatch or session not found');
        }
        
        Log::debug('Keycloak callback: State validation passed');

        // Change code for token
        $code = $request->input('code');
        if (empty($code)) {
            Log::error('Keycloak callback: No code parameter received', [
                'request_all' => $request->all(),
            ]);
            
            KeycloakWeb::forgetState();
            return redirect(route('keycloak.login'));
        }
        
            $token = KeycloakWeb::getAccessToken($code);

        if (empty($token) || empty($token['access_token'])) {
            Log::error('Keycloak callback: Failed to get access token', [
                'code' => $code,
                'token_response' => $token,
            ]);
            
            KeycloakWeb::forgetState();
            throw new KeycloakCallbackException('Failed to get access token from Keycloak');
        }

        // Determine which guard to use based on:
        // 1. Request path (if contains app/tenant)
        // 2. Referer header (if coming from app panel)
        // 3. Session state (if stored during login)
        $guardName = 'keycloak-web';
        
        // Check request path
        if (str_contains($request->path(), 'app') || str_contains($request->path(), 'tenant')) {
            $guardName = 'tenant-keycloak';
        }
        
        // Check referer header (if callback is from app panel login)
        $referer = $request->header('referer');
        if ($referer && (str_contains($referer, '/app/') || str_contains($referer, '/app/login'))) {
            $guardName = 'tenant-keycloak';
        }
        
        // Check session for panel context (stored during login)
        $panelContext = session()->get('keycloak_panel_context');
        if ($panelContext === 'app') {
            $guardName = 'tenant-keycloak';
        }
        
        Log::debug('Keycloak callback: Guard selection', [
            'request_path' => $request->path(),
            'referer' => $referer,
            'panel_context' => $panelContext,
            'selected_guard' => $guardName,
        ]);
        
        Log::debug('Keycloak callback: Validating token with guard', [
            'guard' => $guardName,
            'has_token' => !empty($token),
        ]);
        
        // Use the correct guard to validate token
        // This will save token to session and authenticate user
        if (Auth::guard($guardName)->validate($token)) {
            Log::debug('Keycloak callback: Token validation successful, processing tenant');
            
            // Clear state after successful authentication
            KeycloakWeb::forgetState();
            
            // Get authenticated user
            // validate() should have authenticated the user and saved token to session
            $user = Auth::guard($guardName)->user();
            
            Log::debug('Keycloak callback: User after authentication', [
                'user_exists' => !is_null($user),
                'user_email' => $user->email ?? null,
                'guard' => $guardName,
                'session_token_exists' => !is_null(KeycloakWeb::retrieveToken()),
            ]);
            if (!$user) {
                Log::error('Keycloak callback: User not found after authentication');
                KeycloakWeb::forgetState();
                return redirect(route('keycloak.login'));
            }
            
            // Get user email and name from Keycloak user
            $userEmail = $user->email ?? null;
            $userName = $user->name ?? $userEmail ?? 'User';
            
            if (!$userEmail) {
                Log::error('Keycloak callback: User email not found');
                KeycloakWeb::forgetState();
                return redirect(route('keycloak.login'));
            }
            
            // Try to get tenant for this user
            $tenant = $this->getOrCreateTenantForUser($userEmail, $userName);
            
            if (!$tenant) {
                Log::error('Keycloak callback: Failed to get or create tenant', [
                    'email' => $userEmail,
                ]);
                KeycloakWeb::forgetState();
                return redirect(route('keycloak.login'));
            }
            
            // Generate redirect URL to tenant dashboard
            // Use route helper with tenant parameter
            try {
                // Try to use Filament's route name for tenant dashboard
                $redirectUrl = route('filament.app.pages.dashboard', ['tenant' => $tenant]);
            } catch (\Exception $e) {
                // Fallback to manual URL construction
                Log::warning('Keycloak callback: Failed to generate route, using manual URL', [
                    'error' => $e->getMessage(),
                    'tenant_id' => $tenant->id,
                ]);
                $redirectUrl = '/app/tenant/' . $tenant->getRouteKey();
            }
            
            // Clear panel context from session (no longer needed)
            session()->forget('keycloak_panel_context');
            
            // Ensure session is saved and committed before redirect
            // This is critical for the session to persist across redirects
            session()->save();
            
            // Also commit the session to ensure it's written to storage
            if (method_exists(session()->driver(), 'commit')) {
                session()->driver()->commit();
            }
            
            Log::debug('Keycloak callback: Redirecting to tenant', [
                'redirect_url' => $redirectUrl,
                'tenant_id' => $tenant->id,
                'tenant_route_key' => $tenant->getRouteKey(),
                'tenant_name' => $tenant->name,
                'user_email' => $userEmail,
                'session_id' => session()->getId(),
                'token_in_session' => !is_null(KeycloakWeb::retrieveToken()),
                'user_authenticated' => Auth::guard($guardName)->check(),
                'guard_used' => $guardName,
            ]);
            
            // Use a 303 redirect to prevent POST resubmission issues
            return redirect($redirectUrl, 303);
        } else {
            Log::error('Keycloak callback: Token validation failed', [
                'guard' => $guardName,
                'token_keys' => array_keys($token ?? []),
            ]);
        }

        KeycloakWeb::forgetState();
        return redirect(route('keycloak.login'));
    }
    
    /**
     * Get or create tenant for Keycloak user
     *
     * @param string $email
     * @param string $name
     * @return \App\Models\Tenant|null
     */
    protected function getOrCreateTenantForUser(string $email, string $name)
    {
        try {
            // Check if tenant_user exists for this email
            if (class_exists(\App\Models\Tenant\User::class)) {
                $tenantUser = \App\Models\Tenant\User::where('email', $email)->first();
                
                if ($tenantUser && $tenantUser->tenant) {
                    Log::debug('Keycloak callback: Found existing tenant for user', [
                        'email' => $email,
                        'tenant_id' => $tenantUser->tenant_id,
                    ]);
                    return $tenantUser->tenant;
                }
            }
            
            // No tenant found, create a new tenant
            Log::debug('Keycloak callback: Creating new tenant for user', [
                'email' => $email,
                'name' => $name,
            ]);
            
            return $this->createTenantForUser($email, $name);
        } catch (\Exception $e) {
            Log::error('Keycloak callback: Error getting or creating tenant', [
                'email' => $email,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);
            return null;
        }
    }
    
    /**
     * Create tenant and tenant user for Keycloak user
     *
     * @param string $email
     * @param string $name
     * @return \App\Models\Tenant|null
     */
    protected function createTenantForUser(string $email, string $name)
    {
        if (!class_exists(\App\Models\Tenant::class) || !class_exists(\App\Services\TenantPermissionService::class)) {
            Log::error('Keycloak callback: Required classes not found for tenant creation');
            return null;
        }
        
        return DB::transaction(function () use ($email, $name) {
            // Create tenant
            $tenant = \App\Models\Tenant::create([
                'name' => $name . ' Tenant',
                'email' => $email,
                'status' => 'active',
            ]);
            
            Log::debug('Keycloak callback: Tenant created', [
                'tenant_id' => $tenant->id,
                'tenant_name' => $tenant->name,
            ]);
            
            // Initialize tenant permissions and create admin user
            $permissionService = app(\App\Services\TenantPermissionService::class);
            
            // Create tenant admin user (password is not needed for Keycloak users)
            // But TenantPermissionService requires password, so we'll use a random one
            // The user will login via Keycloak anyway
            $randomPassword = bin2hex(random_bytes(16));
            
            $admin = $permissionService->initializeTenantPermissions($tenant, [
                'name' => $name,
                'email' => $email,
                'password' => $randomPassword, // Not used for Keycloak auth
            ]);
            
            Log::debug('Keycloak callback: Tenant admin user created', [
                'tenant_id' => $tenant->id,
                'admin_email' => $admin->email,
            ]);
            
            return $tenant;
        });
    }
}
