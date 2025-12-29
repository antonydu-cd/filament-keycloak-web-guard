<?php

namespace Ebrook\KeycloakWebGuard\Auth\Guard;

use Illuminate\Auth\Events\Authenticated;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
use Ebrook\KeycloakWebGuard\Auth\KeycloakAccessToken;
use Ebrook\KeycloakWebGuard\Exceptions\KeycloakCallbackException;
use Ebrook\KeycloakWebGuard\Models\KeycloakUser;
use Ebrook\KeycloakWebGuard\Facades\KeycloakWeb;
use Illuminate\Contracts\Auth\UserProvider;

class KeycloakWebGuard implements Guard
{
    /**
     * @var null|Authenticatable|KeycloakUser
     */
    protected $user;

    /**
     * @var UserProvider
     */
    protected $provider;

    /**
     * @var Request
     */
    protected $request;

    public function __construct(UserProvider $provider, Request $request)
    {
        $this->provider = $provider;
        $this->request = $request;
    }

    /**
     * Determine if the current user is authenticated.
     *
     * @return bool
     */
    public function check()
    {
        return (bool) $this->user();
    }

    /**
     * @return bool
     */
    public function hasUser()
    {
        return (bool) $this->user;
    }

    /**
     * Determine if the current user is a guest.
     *
     * @return bool
     */
    public function guest()
    {
        return ! $this->check();
    }

    /**
     * Get the currently authenticated user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function user()
    {
        if (empty($this->user)) {
            $this->authenticate();
        }

        return $this->user;
    }

    /**
     * Set the current user.
     *
     * @param \Illuminate\Contracts\Auth\Authenticatable $user
     * @return void
     */
    public function setUser(?Authenticatable $user)
    {
        $this->user = $user;
    }

    /**
     * Get the ID for the currently authenticated user.
     *
     * @return int|string|null
     */
    public function id()
    {
        $user = $this->user();
        return $user->id ?? null;
    }

    /**
    * Disable viaRemember methode used by some bundles (like filament)
    *
    * @return bool
    */
    public function viaRemember()
    {
        return false;
    }

    /**
     * Validate a user's credentials.
     *
     * @param  array  $credentials
     *
     * @throws BadMethodCallException
     *
     * @return bool
     */
    public function validate(array $credentials = [])
    {
        if (empty($credentials['access_token']) || empty($credentials['id_token'])) {
            return false;
        }

        /**
         * Store the section
         */
        $credentials['refresh_token'] = $credentials['refresh_token'] ?? '';
        KeycloakWeb::saveToken($credentials);

        return $this->authenticate();
    }

    /**
     * Try to authenticate the user
     *
     * @throws KeycloakCallbackException
     * @return bool
     */
    public function authenticate()
    {
        // Get Credentials
        $credentials = KeycloakWeb::retrieveToken();
        if (empty($credentials)) {
            return false;
        }

        $user = KeycloakWeb::getUserProfile($credentials);
        if (empty($user)) {
            // 对于API请求（从请求头获取token），不清理session
            // 只清理session中的token（如果有）
            if (session()->has('_keycloak_token')) {
                KeycloakWeb::forgetToken();
            }

            // 记录认证失败的日志，但不抛出异常
            // 让Laravel的认证系统自动重定向到登录页面
            \Illuminate\Support\Facades\Log::info('Keycloak authentication failed, token may be expired or invalid', [
                'reason' => 'user_profile_empty',
                'has_credentials' => !empty($credentials),
                'debug_mode' => \Illuminate\Support\Facades\Config::get('app.debug', false),
            ]);

            return false;
        }

        // For tenant guard, ensure tenant context is available before provider call
        if ($this->provider instanceof \App\Auth\TenantKeycloakUserProvider) {
            // Check if we need to set tenant context from global state
            if (!session()->has('current_tenant_id')) {
                // Try to get tenant info from any available source
                $pendingTenantInstanceId = session('pending_tenant_instance_id');
                if ($pendingTenantInstanceId) {
                    $tenant = \App\Models\Tenant::where('tenant_instance_id', $pendingTenantInstanceId)->first();
                    if ($tenant) {
                        session(['current_tenant_id' => $tenant->id]);
                        session()->save(); // Ensure it's saved immediately
                        \Illuminate\Support\Facades\Log::info('KeycloakWebGuard: Set tenant context from pending instance ID', [
                            'tenant_id' => $tenant->id,
                            'tenant_instance_id' => $pendingTenantInstanceId,
                        ]);
                    }
                }
            }

            \Illuminate\Support\Facades\Log::debug('KeycloakWebGuard: Authenticating tenant user', [
                'has_tenant_context' => session()->has('current_tenant_id'),
                'user_email' => $user['email'] ?? 'unknown',
            ]);
        }

        // Provide User
        $user = $this->provider->retrieveByCredentials($user);
        $this->setUser($user);

        event(new Authenticated(Auth::getDefaultDriver(), Auth()->user()));

        return true;
    }

    /**
     * Check user is authenticated and return his resource roles
     *
     * @param string $resource Default is empty: point to client_id
     *
     * @return bool|array
    */
    public function roles($resource = '')
    {
        if (empty($resource)) {
            $resource = Config::get('keycloak-web.client_id');
        }

        if (! $this->check()) {
            return false;
        }

        $token = KeycloakWeb::retrieveToken();

        if (empty($token) || empty($token['access_token'])) {
            return false;
        }

        $token = new KeycloakAccessToken($token);
        $token = $token->parseAccessToken();

        $resourceRoles = $token['resource_access'] ?? [];
        $resourceRoles = $resourceRoles[ $resource ] ?? [];
        $resourceRoles = $resourceRoles['roles'] ?? [];

        $realmRoles = $token['realm_access'] ?? [];
        $realmRoles = $realmRoles['roles'] ?? [];

        return array_merge($resourceRoles, $realmRoles);
    }

    /**
     * Check user has a role
     *
     * @param array|string $roles
     * @param string $resource Default is empty: point to client_id
     *
     * @return bool
     */
    public function hasRole($roles, $resource = '')
    {
        return empty(array_diff((array) $roles, $this->roles($resource)));
    }

    /**
     * Log the user out for guard consumers (e.g. Filament).
     *
     * Session invalidation/regeneration is handled by Filament's LogoutController,
     * so we only clear Keycloak tokens and the in-memory user here.
     */
    public function logout(): void
    {
        // KeycloakWeb::forgetToken();
        $this->user = null;
    }

    /**
     * Log the user out of the current device.
     *
     * This method is called by Laravel's AuthenticateSession middleware
     * when it detects that the user's password has changed.
     *
     * @return void
     */
    public function logoutCurrentDevice(): void
    {
        $user = $this->user();

        // Clear Keycloak token from session
        KeycloakWeb::forgetToken();

        // Clear the in-memory user
        $this->user = null;

        // For Keycloak, we don't need to clear session data as extensively
        // as SessionGuard does, since authentication is token-based
    }
}
