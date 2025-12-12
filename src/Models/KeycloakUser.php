<?php

namespace Ebrook\KeycloakWebGuard\Models;

use Auth;
use Filament\Models\Contracts\FilamentUser;
use Filament\Models\Contracts\HasTenants;
use Filament\Panel;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Access\Authorizable;
use Illuminate\Contracts\Auth\Access\Gate;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Gate as GateFacade;

class KeycloakUser implements Authenticatable, Authorizable, FilamentUser, HasTenants
{
    /**
     * Attributes we retrieve from Profile
     *
     * @var array
     */
    protected $fillable = [
        'name',
        'email'
    ];

    /**
     * User attributes
     *
     * @var array
     */
    protected $attributes = [];

    /**
     * @var mixed
     */
    protected $id;

    /**
     * @var mixed|null
     */
    protected $email;

    /**
     * Constructor
     *
     * @param array $profile Keycloak user info
     */
    public function __construct(array $profile)
    {
        foreach ($profile as $key => $value) {
            if (in_array($key, $this->fillable)) {
                $this->attributes[ $key ] = $value;
            }
        }

        $this->id = $this->getKey();
    }

    /**
     * Magic method to get attributes
     *
     * @param  string $name
     * @return mixed
     */
    public function __get(string $name)
    {
        return $this->attributes[ $name ] ?? null;
    }

    /**
     * Allow framework callers to retrieve attribute values.
     *
     * Filament expects Eloquent-like users with getAttributeValue().
     */
    public function getAttributeValue(string $key)
    {
        return $this->__get($key);
    }

    /**
     * Get the value of the model's primary key.
     *
     * @return mixed
     */
    public function getKey()
    {
        return $this->email;
    }

    /**
     * Get the name of the unique identifier for the user.
     *
     * @return string
     */
    public function getAuthIdentifierName()
    {
        return 'email';
    }

    /**
     * Get the unique identifier for the user.
     *
     * @return mixed
     */
    public function getAuthIdentifier()
    {
        return $this->getEmail();
    }
    
    /**
     * Get the email address of the user.
     *
     * @return string|null
     */
    public function getEmail()
    {
        return $this->attributes['email'] ?? $this->email ?? null;
    }

    /**
     * Check user has roles
     *
     * @see KeycloakWebGuard::hasRole()
     *
     * @param  string|array  $roles
     * @param  string  $resource
     * @return boolean
     */
    public function hasRole($roles, $resource = '')
    {
        return Auth::hasRole($roles, $resource);
    }

    /**
     * Determine if the entity has the given abilities.
     *
     * @param  iterable|string  $abilities
     * @param  array|mixed  $arguments
     * @return bool
     */
    public function can($abilities, $arguments = [])
    {
        // Try to find mapped Laravel User first
        $laravelUser = $this->getMappedLaravelUser();
        
        if ($laravelUser) {
            // Use Laravel User's permission system (Spatie Permission)
            return $laravelUser->can($abilities, $arguments);
        }
        
        // Fallback to Gate system for Keycloak users
        // Gate supports non-Eloquent users
        return GateFacade::forUser($this)->allows($abilities, $arguments);
    }

    /**
     * Determine if the entity does not have the given abilities.
     *
     * @param  iterable|string  $abilities
     * @param  array|mixed  $arguments
     * @return bool
     */
    public function cannot($abilities, $arguments = [])
    {
        return !$this->can($abilities, $arguments);
    }

    /**
     * Get the mapped Laravel User if exists.
     * This will be used when user mapping system is implemented.
     *
     * @return \App\Models\User|null
     */
    protected function getMappedLaravelUser()
    {
        // TODO: Implement user mapping lookup when mapping system is ready
        // For now, try to find by email
        if (!$this->email) {
            return null;
        }

        // Check if there's a User model with the same email
        if (class_exists(\App\Models\User::class)) {
            try {
                return \App\Models\User::where('email', $this->email)->first();
            } catch (\Exception $e) {
                // Database might not be ready or table doesn't exist
                return null;
            }
        }

        return null;
    }

    /**
     * Get the gate instance for the entity.
     *
     * @return \Illuminate\Contracts\Auth\Access\Gate
     */
    public function getGate(): Gate
    {
        return GateFacade::forUser($this);
    }

    /**
     * Get the password for the user.
     *
     * @return string
     */
    public function getAuthPassword()
    {
        // Password-based auth is not used for Keycloak users.
        // Returning an empty string prevents session guard callers from failing.
        return '';
    }

    /**
     * Get the token value for the "remember me" session.
     *
     * @return string
     * @codeCoverageIgnore
     */
    public function getRememberToken()
    {
        return null;
    }

    /**
     * Set the token value for the "remember me" session.
     *
     * @param string $value
     * @codeCoverageIgnore
     */
    public function setRememberToken($value)
    {
        // Keycloak authentication does not persist remember tokens.
    }

    /**
     * Get the column name for the "remember me" token.
     *
     * @return string
     * @codeCoverageIgnore
     */
    public function getRememberTokenName()
    {
        return 'remember_token';
    }

    /**
     * Get the name of the password attribute for the user.
     *
     * @return string
     * @codeCoverageIgnore
     */
    public function getAuthPasswordName()
    {
        return 'password';
    }

    /**
     * Determine if the user can access the given Filament panel.
     *
     * @param  Panel  $panel
     * @return bool
     */
    public function canAccessPanel(Panel $panel): bool
    {
        return true;
    }

    /**
     * Get the user's name for Filament.
     *
     * @return string
     */
    public function getFilamentName(): string
    {
        return $this->name ?? $this->email ?? 'User';
    }

    /**
     * Get the tenants that the user belongs to.
     *
     * @param  Panel  $panel
     * @return Collection
     */
    public function getTenants(Panel $panel): Collection
    {
        // Try to get tenants from mapped Laravel User first
        $laravelUser = $this->getMappedLaravelUser();
        
        if ($laravelUser && method_exists($laravelUser, 'getTenants')) {
            return $laravelUser->getTenants($panel);
        }
        
        // If no mapped user, try to find tenants via tenant_users table
        if ($this->email) {
            try {
                // Check if Tenant\User model exists and find by email
                if (class_exists(\App\Models\Tenant\User::class)) {
                    $tenantUsers = \App\Models\Tenant\User::where('email', $this->email)->get();
                    if ($tenantUsers->isNotEmpty()) {
                        $tenants = $tenantUsers->map(function ($tenantUser) {
                            return $tenantUser->tenant;
                        })->filter();
                        
                        return new Collection($tenants);
                    }
                }
                
                // Also check central User model's tenant relationship
                if (class_exists(\App\Models\User::class) && class_exists(\App\Models\Tenant::class)) {
                    $centralUser = \App\Models\User::where('email', $this->email)->first();
                    if ($centralUser && method_exists($centralUser, 'tenants')) {
                        return $centralUser->tenants;
                    }
                }
            } catch (\Exception $e) {
                // Database might not be ready or table doesn't exist
                // Log error but don't fail
            }
        }
        
        // Return empty collection if no tenants found
        return new Collection([]);
    }

    /**
     * Determine if the user can access the given tenant.
     *
     * @param  Model  $tenant
     * @return bool
     */
    public function canAccessTenant(Model $tenant): bool
    {
        // Get email - try multiple ways to access it
        $email = $this->getEmail();
        if (!$email && isset($this->attributes['email'])) {
            $email = $this->attributes['email'];
        }
        if (!$email && property_exists($this, 'email')) {
            $email = $this->email;
        }
        
        \Illuminate\Support\Facades\Log::debug('KeycloakUser canAccessTenant: Starting check', [
            'email_from_getEmail' => $this->getEmail(),
            'email_from_attributes' => $this->attributes['email'] ?? 'not set',
            'email_from_property' => $this->email ?? 'not set',
            'final_email' => $email,
            'tenant_id' => $tenant->getKey(),
        ]);
        
        // Try to get access check from mapped Laravel User first
        $laravelUser = $this->getMappedLaravelUser();
        
        if ($laravelUser && method_exists($laravelUser, 'canAccessTenant')) {
            $result = $laravelUser->canAccessTenant($tenant);
            \Illuminate\Support\Facades\Log::debug('KeycloakUser canAccessTenant: Checked via mapped user', [
                'result' => $result,
            ]);
            return $result;
        }
        
        // Check via tenant_users table
        if ($email && $tenant) {
            try {
                // Check Tenant\User model
                if (class_exists(\App\Models\Tenant\User::class)) {
                    // Use getKey() to get the tenant ID (handles both integer and string IDs)
                    $tenantId = $tenant->getKey();
                    $tenantUser = \App\Models\Tenant\User::where('email', $email)
                        ->where('tenant_id', $tenantId)
                        ->first();
                    
                    if ($tenantUser) {
                        \Illuminate\Support\Facades\Log::debug('KeycloakUser canAccessTenant: Found tenant user', [
                            'email' => $email,
                            'tenant_id' => $tenantId,
                            'tenant_user_id' => $tenantUser->id,
                        ]);
                        return true;
                    }
                    
                    \Illuminate\Support\Facades\Log::debug('KeycloakUser canAccessTenant: Tenant user not found', [
                        'email' => $email,
                        'tenant_id' => $tenantId,
                        'tenant_key' => $tenant->getKey(),
                    ]);
                }
                
                // Check central User model's tenant relationship
                if (class_exists(\App\Models\User::class)) {
                    $centralUser = \App\Models\User::where('email', $email)->first();
                    if ($centralUser && method_exists($centralUser, 'tenants')) {
                        $hasAccess = $centralUser->tenants->contains($tenant);
                        \Illuminate\Support\Facades\Log::debug('KeycloakUser canAccessTenant: Checked central user tenants', [
                            'email' => $email,
                            'has_access' => $hasAccess,
                        ]);
                        return $hasAccess;
                    }
                }
            } catch (\Exception $e) {
                \Illuminate\Support\Facades\Log::error('KeycloakUser canAccessTenant: Exception', [
                    'email' => $email,
                    'error' => $e->getMessage(),
                ]);
            }
        }
        
        // Default to false if no access found
        \Illuminate\Support\Facades\Log::debug('KeycloakUser canAccessTenant: Returning false', [
            'email' => $email ?? 'no email',
            'tenant_id' => $tenant->getKey() ?? 'no tenant id',
        ]);
        return false;
    }
}
