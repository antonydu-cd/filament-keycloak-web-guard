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

        // If the model is an Eloquent model and we have an email, try to find the user in database
        if ($email && is_subclass_of($class, \Illuminate\Database\Eloquent\Model::class)) {
            $user = $class::where('email', $email)->first();
            
            if ($user) {
                // Return the database user instance with all relationships (roles, permissions, etc.)
                return $user;
            }
            
            // If user not found in database, return null to deny access
            // (only existing users with assigned roles can login)
            return null;
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
