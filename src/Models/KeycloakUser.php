<?php

namespace Ebrook\KeycloakWebGuard\Models;

use Auth;
use Filament\Models\Contracts\FilamentUser;
use Filament\Panel;
use Illuminate\Contracts\Auth\Authenticatable;

class KeycloakUser implements Authenticatable, FilamentUser
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
        return $this->email;
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
}
