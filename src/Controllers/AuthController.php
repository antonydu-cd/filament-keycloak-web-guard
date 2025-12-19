<?php

namespace Ebrook\KeycloakWebGuard\Controllers;

use Illuminate\Auth\Events\Logout;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\Str;
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
        $url = KeycloakWeb::getLoginUrl();
        KeycloakWeb::saveState();

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
      
        $guard = Config::get('keycloak-web.guard', 'web');
        event(new Logout($guard, Auth::guard($guard)->user()));
      
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
        // Check for errors from Keycloak
        if (! empty($request->input('error'))) {
            $error = $request->input('error_description');
            $error = ($error) ?: $request->input('error');

            throw new KeycloakCallbackException($error);
        }

        // Check given state to mitigate CSRF attack
        $state = $request->input('state');
        if (empty($state) || ! KeycloakWeb::validateState($state)) {
            KeycloakWeb::forgetState();

            throw new KeycloakCallbackException('Invalid state');
        }

        // Change code for token
        $code = $request->input('code');
        if (! empty($code)) {
            $token = KeycloakWeb::getAccessToken($code);

            $guard = Config::get('keycloak-web.guard', 'web');
            if (Auth::guard($guard)->validate($token)) {
                // Clear any intended URL from session to prevent redirect to wrong panel
                Session::forget('url.intended');
                
                // Always use the configured redirect URL for this guard
                $url = config('keycloak-web.redirect_url', '/app');
                return redirect($url);
            }
        }

        return redirect(route('keycloak.login'));
    }
}
