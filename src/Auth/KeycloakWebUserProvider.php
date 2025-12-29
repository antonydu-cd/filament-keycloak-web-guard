<?php

namespace Ebrook\KeycloakWebGuard\Auth;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Ebrook\KeycloakWebGuard\Models\KeycloakUser;

class KeycloakWebUserProvider implements UserProvider
{
    /**
     * The user model.
     *
     * @var string
     */
    protected $model;

    /**
     * The Constructor
     *
     * @param string $model
     */
    public function __construct($model)
    {
        $this->model = $model;
    }

    /**
     * Retrieve a user by the given credentials.
     *
     * @param  array  $credentials
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function retrieveByCredentials(array $credentials)
    {
        $class = '\\'.ltrim($this->model, '\\');

        // Get the email from credentials (Keycloak returns user profile with email)
        $email = $credentials['email'] ?? null;
        $keycloakUserId = $credentials['sub'] ?? null;
        $name = $credentials['name'] ?? $credentials['preferred_username'] ?? $email;

        // If the model is an Eloquent model and we have an email, try to find the user in database
        if ($email && is_subclass_of($class, \Illuminate\Database\Eloquent\Model::class)) {
            // First, try to find by email (without global scopes to search across all tenants)
            $user = $class::withoutGlobalScopes()->where('email', $email)->first();
            
            if ($user) {
                // Update keycloak_user_id if not set
                if ($keycloakUserId && empty($user->keycloak_user_id)) {
                    $user->keycloak_user_id = $keycloakUserId;
                    $user->save();
                }
                
                // Return the database user instance with all relationships (roles, permissions, etc.)
                return $user;
            }
            
            // If user not found, try to find by keycloak_user_id (without global scopes)
            if ($keycloakUserId) {
                $user = $class::withoutGlobalScopes()->where('keycloak_user_id', $keycloakUserId)->first();
                if ($user) {
                    // Update email if changed
                    if ($user->email !== $email) {
                        $user->email = $email;
                        $user->save();
                    }
                    return $user;
                }
            }
            
            // User not found, create new user automatically
            try {
                // Try to get tenant from Filament context
                $tenantId = null;
                if (class_exists(\Filament\Facades\Filament::class)) {
                    $tenant = \Filament\Facades\Filament::getTenant();
                    if ($tenant) {
                        $tenantId = $tenant->id;
                    }
                }
                
                // If no tenant from Filament, try to get from session
                if (!$tenantId && session()->has('current_tenant_id')) {
                    $tenantId = session('current_tenant_id');
                }
                
                // If no tenant from session, try to get from URL route parameter
                if (!$tenantId && request()->route('tenant')) {
                    $tenantParam = request()->route('tenant');
                    if (is_numeric($tenantParam)) {
                        $tenantId = (int) $tenantParam;
                    } elseif (is_object($tenantParam) && method_exists($tenantParam, 'getKey')) {
                        $tenantId = $tenantParam->getKey();
                    }
                }
                
                // If still no tenant, try to find a default tenant (first active tenant)
                if (!$tenantId) {
                    $tenantModel = '\\App\\Models\\Tenant';
                    if (class_exists($tenantModel)) {
                        $defaultTenant = $tenantModel::where('status', 'active')->first();
                        if ($defaultTenant) {
                            $tenantId = $defaultTenant->id;
                        }
                    }
                }
                
                // If still no tenant, try to find any tenant (regardless of status)
                if (!$tenantId) {
                    $tenantModel = '\\App\\Models\\Tenant';
                    if (class_exists($tenantModel)) {
                        $anyTenant = $tenantModel::first();
                        if ($anyTenant) {
                            $tenantId = $anyTenant->id;
                        }
                    }
                }
                
                // If still no tenant, create a default tenant automatically
                if (!$tenantId) {
                    $tenantModel = '\\App\\Models\\Tenant';
                    if (class_exists($tenantModel)) {
                        try {
                            // Generate unique email for default tenant
                            $defaultEmail = 'default-' . time() . '@tenant.local';
                            $counter = 1;
                            while ($tenantModel::where('email', $defaultEmail)->exists()) {
                                $defaultEmail = 'default-' . time() . '-' . $counter . '@tenant.local';
                                $counter++;
                            }
                            
                            $defaultTenant = $tenantModel::create([
                                'name' => 'Default Tenant',
                                'email' => $defaultEmail,
                                'status' => 'active',
                                'auto_created' => true,
                            ]);
                            
                            $tenantId = $defaultTenant->id;
                        } catch (\Exception $e) {
                            \Illuminate\Support\Facades\Log::error('KeycloakWebUserProvider::retrieveByCredentials Failed to create default tenant', [
                                'error' => $e->getMessage(),
                                'trace' => $e->getTraceAsString(),
                            ]);
                        }
                    }
                }
                
                // If still no tenant, we cannot create user (tenant_id is required)
                if (!$tenantId) {
                    \Illuminate\Support\Facades\Log::error('KeycloakWebUserProvider::retrieveByCredentials Cannot create user: no tenant context', [
                        'email' => $email,
                        'keycloak_user_id' => $keycloakUserId,
                    ]);
                    return null;
                }
                
                // Create user data
                $userData = [
                    'tenant_id' => $tenantId,
                    'email' => $email,
                    'name' => $name,
                    'keycloak_user_id' => $keycloakUserId,
                    'status' => 'active',
                    'email_verified_at' => now(),
                    'password' => bcrypt(\Illuminate\Support\Str::random(32)), // Random password for Keycloak users
                ];
                
                // Create user (without global scope to avoid tenant filtering issues)
                $user = $class::withoutGlobalScopes()->create($userData);
                
                // Assign super_admin role to the user
                try {
                    $roleModel = '\\App\\Models\\Role';
                    $permissionRegistrar = app(\Spatie\Permission\PermissionRegistrar::class);
                    
                    if (class_exists($roleModel) && $user->tenant_id) {
                        // Set permissions team ID (tenant ID) for role assignment
                        $permissionRegistrar->setPermissionsTeamId($user->tenant_id);
                        
                        // Find or create super_admin role for this tenant
                        $superAdminRole = $roleModel::withoutGlobalScopes()->firstOrCreate([
                            'name' => 'super_admin',
                            'guard_name' => 'tenant',
                            'tenant_id' => $user->tenant_id,
                        ], [
                            'name' => 'super_admin',
                            'guard_name' => 'tenant',
                            'tenant_id' => $user->tenant_id,
                        ]);
                        
                        // Assign super_admin role to user
                        $user->roles()->attach($superAdminRole->id, ['tenant_id' => $user->tenant_id]);
                    }
                } catch (\Exception $e) {
                    \Illuminate\Support\Facades\Log::error('KeycloakWebUserProvider::retrieveByCredentials Failed to assign super_admin role to user', [
                        'user_id' => $user->id,
                        'error' => $e->getMessage(),
                        'trace' => $e->getTraceAsString(),
                    ]);
                    // Don't fail user creation if role assignment fails
                }
                
                return $user;
            } catch (\Exception $e) {
                \Illuminate\Support\Facades\Log::error('KeycloakWebUserProvider::retrieveByCredentials Failed to create user', [
                    'error' => $e->getMessage(),
                    'trace' => $e->getTraceAsString(),
                ]);
                
                // If creation fails, return null to deny access
                return null;
            }
        }

        // Fallback to original behavior for non-Eloquent models (e.g., KeycloakUser)
        return new $class($credentials);
    }

    /**
     * Retrieve a user by their unique identifier.
     *
     * @param  mixed  $identifier
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function retrieveById($identifier)
    {
        throw new \BadMethodCallException('Unexpected method [retrieveById] call');
    }

    /**
     * Retrieve a user by their unique identifier and "remember me" token.
     *
     * @param  mixed  $identifier
     * @param  string  $token
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function retrieveByToken($identifier, $token)
    {
        throw new \BadMethodCallException('Unexpected method [retrieveByToken] call');
    }

    /**
     * Update the "remember me" token for the given user in storage.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  string  $token
     * @return void
     */
    public function updateRememberToken(Authenticatable $user, $token)
    {
        throw new \BadMethodCallException('Unexpected method [updateRememberToken] call');
    }

    /**
     * Validate a user against the given credentials.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  array  $credentials
     * @return bool
     */
    public function validateCredentials(Authenticatable $user, array $credentials)
    {
        throw new \BadMethodCallException('Unexpected method [validateCredentials] call');
    }

    /**
     * Rehash the user's password if required and supported.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  array  $credentials
     * @param  bool  $force
     * @return void
     */
    public function rehashPasswordIfRequired(Authenticatable $user, array $credentials, bool $force = false)
    {
        throw new \BadMethodCallException('Unexpected method [rehashPasswordIfRequired] call');
    }
}
