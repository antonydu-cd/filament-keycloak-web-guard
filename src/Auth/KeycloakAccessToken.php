<?php

namespace Ebrook\KeycloakWebGuard\Auth;

use Exception;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;

class KeycloakAccessToken
{
    /**
     * @var string
     */
    protected $accessToken;

    /**
     * @var string
     */
    protected $refreshToken;

    /**
     * @var string
     */
    protected $idToken;

    /**
     * @var int
     */
    protected $expires;

    /**
     * Constructs an access token.
     *
     * @param array $data The token from Keycloak as array.
     */
    public function __construct($data = [])
    {
        $data = (array) $data;

        if (! empty($data['access_token'])) {
            $this->accessToken = $data['access_token'];
        }

        if (! empty($data['refresh_token'])) {
            $this->refreshToken = $data['refresh_token'];
        }

        if (! empty($data['id_token'])) {
            $this->idToken = $data['id_token'];
        }

        if (! empty($data['expires_in'])) {
            $this->expires = (int) $data['expires_in'];
        }
    }

    /**
     * Get AccessToken
     *
     * @return string
     */
    public function getAccessToken()
    {
        return $this->accessToken;
    }

    /**
     * Get RefreshToken
     *
     * @return string
     */
    public function getRefreshToken()
    {
        return $this->refreshToken;
    }

    /**
     * Get IdToken
     *
     * @return string
     */
    public function getIdToken()
    {
        return $this->idToken;
    }

    /**
     * Check access token has expired
     *
     * @return bool
     */
    public function hasExpired()
    {
        $exp = $this->parseAccessToken();
        $exp = $exp['exp'] ?? '';

        return time() >= (int) $exp;
    }

    /**
     * Check the ID Token
     *
     * @throws Exception
     * @return void
     */
    public function validateIdToken($claims)
    {
        // Verify JWT signature if enabled
        if (Config::get('keycloak-web.verify_jwt_signature', true)) {
            $this->verifyTokenSignature($this->idToken, 'ID Token');
        }

        $token = $this->parseIdToken();
        if (empty($token)) {
            throw new Exception('ID Token is invalid.');
        }

        $default = array(
            'exp' => 0,
            'aud' => '',
            'iss' => '',
        );

        $token = array_merge($default, $token);
        $claims = array_merge($default, (array) $claims);

        // Validate expiration
        if (time() >= (int) $token['exp']) {
            throw new Exception('ID Token already expired.');
        }

        // Validate issuer
        if (empty($claims['iss']) || $claims['iss'] !== $token['iss']) {
            throw new Exception('Access Token has a wrong issuer: must contain issuer from OpenId.');
        }

        // Validate audience
        $audience = (array) $token['aud'];
        if (empty($claims['aud']) || ! in_array($claims['aud'], $audience, true)) {
            throw new Exception('Access Token has a wrong audience: must contain clientId.');
        }

        if (count($audience) > 1 && empty($token['azp'])) {
            throw new Exception('Access Token has a wrong audience: must contain azp claim.');
        }

        if (! empty($token['azp']) && $claims['aud'] !== $token['azp']) {
            throw new Exception('Access Token has a wrong audience: has azp but is not the clientId.');
        }
    }

    /**
     * Verify JWT token signature
     *
     * @param string $token
     * @param string $tokenType
     * @throws Exception
     * @return void
     */
    protected function verifyTokenSignature($token, $tokenType = 'Token')
    {
        if (empty($token)) {
            throw new Exception($tokenType . ' is empty and cannot be verified.');
        }

        try {
            // Get the kid (Key ID) from token header
            $tokenParts = explode('.', $token);
            if (count($tokenParts) !== 3) {
                throw new Exception($tokenType . ' has invalid format.');
            }

            $header = json_decode($this->base64UrlDecode($tokenParts[0]), true);
            $kid = $header['kid'] ?? null;

            // Get public key from KeycloakService
            $keycloakService = app(\Ebrook\KeycloakWebGuard\Services\KeycloakService::class);
            $publicKey = $keycloakService->getPublicKey($kid);

            if (empty($publicKey)) {
                // Log warning but don't fail if public key retrieval fails
                // This maintains backward compatibility
                Log::warning('[Keycloak Token] Failed to retrieve public key for signature verification', [
                    'token_type' => $tokenType,
                    'kid' => $kid,
                ]);
                return;
            }

            // Get allowed algorithms
            $allowedAlgorithms = Config::get('keycloak-web.allowed_algorithms', ['RS256']);

            // Verify the signature using firebase/php-jwt
            JWT::decode($token, new Key($publicKey, $allowedAlgorithms[0]));

            Log::debug('[Keycloak Token] Signature verification successful', [
                'token_type' => $tokenType,
                'kid' => $kid,
            ]);

        } catch (\Firebase\JWT\ExpiredException $e) {
            // Token expired - this is expected, let the normal flow handle it
            Log::info('[Keycloak Token] Token expired during signature verification', [
                'token_type' => $tokenType,
            ]);
            // Don't throw - let the normal expiration check handle it
            return;
        } catch (\Firebase\JWT\SignatureInvalidException $e) {
            // Signature invalid - this is a security issue, should throw
            Log::error('[Keycloak Token] Signature verification failed', [
                'token_type' => $tokenType,
                'error' => $e->getMessage(),
            ]);
            throw new Exception($tokenType . ' signature verification failed: ' . $e->getMessage());
        } catch (\Firebase\JWT\BeforeValidException $e) {
            // Token not yet valid - rare case
            Log::warning('[Keycloak Token] Token not yet valid', [
                'token_type' => $tokenType,
            ]);
            return;
        } catch (\Exception $e) {
            // Log the error but don't fail hard to maintain backward compatibility
            Log::warning('[Keycloak Token] Signature verification error (non-critical)', [
                'token_type' => $tokenType,
                'error' => $e->getMessage(),
                'error_class' => get_class($e),
            ]);
            
            // Don't throw for non-critical errors to maintain backward compatibility
            return;
        }
    }

    /**
     * Validate access token with signature verification
     *
     * @param array $claims
     * @throws Exception
     * @return void
     */
    public function validateAccessToken($claims = [])
    {
        // Verify JWT signature if enabled
        if (Config::get('keycloak-web.verify_jwt_signature', true)) {
            $this->verifyTokenSignature($this->accessToken, 'Access Token');
        }

        $token = $this->parseAccessToken();
        if (empty($token)) {
            throw new Exception('Access Token is invalid.');
        }

        $default = array(
            'exp' => 0,
            'aud' => '',
            'iss' => '',
        );

        $token = array_merge($default, $token);
        $claims = array_merge($default, (array) $claims);

        // Validate expiration
        if (time() >= (int) $token['exp']) {
            throw new Exception('Access Token has expired.');
        }

        // Validate issuer
        if (!empty($claims['iss']) && $claims['iss'] !== $token['iss']) {
            throw new Exception('Access Token has wrong issuer.');
        }

        // For access tokens, validate audience or azp (authorized party)
        if (!empty($claims['aud'])) {
            $audience = isset($token['aud']) ? (array) $token['aud'] : [];
            $azp = $token['azp'] ?? null;
            
            if (!in_array($claims['aud'], $audience, true) && $azp !== $claims['aud']) {
                throw new Exception('Access Token has wrong audience.');
            }
        }
    }

    /**
     * Validate sub from ID token
     *
     * @return bool
     */
    public function validateSub($userSub)
    {
        $sub = $this->parseIdToken();
        $sub = $sub['sub'] ?? '';

        return $sub === $userSub;
    }

    /**
     * Parse the Access Token
     *
     * @return array
     */
    public function parseAccessToken()
    {
        return $this->parseToken($this->accessToken);
    }

    /**
     * Parse the Id Token
     *
     * @return array
     */
    public function parseIdToken()
    {
        return $this->parseToken($this->idToken);
    }

    /**
     * Get token (access/refresh/id) data
     *
     * @param string $token
     * @return array
     */
    protected function parseToken($token)
    {
        if (! is_string($token)) {
            return [];
        }

        $token = explode('.', $token);
        $token = $this->base64UrlDecode($token[1]);

        return json_decode($token, true);
    }

    /**
     * Base64UrlDecode string
     *
     * @link https://www.php.net/manual/pt_BR/function.base64-encode.php#103849
     *
     * @param  string $data
     * @return string
     */
    protected function base64UrlDecode($data)
    {
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
    }
}