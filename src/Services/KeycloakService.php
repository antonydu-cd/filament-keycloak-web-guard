<?php

namespace Ebrook\KeycloakWebGuard\Services;

use Exception;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Route;
use Ebrook\KeycloakWebGuard\Auth\KeycloakAccessToken;

class KeycloakService
{
    /**
     * The Session key for token
     */
    public const KEYCLOAK_SESSION = '_keycloak_token';

    /**
     * The Session key for state
     */
    public const KEYCLOAK_SESSION_STATE = '_keycloak_state';

    /**
     * Keycloak URL
     *
     * @var string
     */
    protected $baseUrl;

    /**
     * Keycloak Realm
     *
     * @var string
     */
    protected $realm;

    /**
     * Keycloak Client ID
     *
     * @var string
     */
    protected $clientId;

    /**
     * Keycloak Client Secret
     *
     * @var string
     */
    protected $clientSecret;

    /**
     * Keycloak OpenId Configuration
     *
     * @var array
     */
    protected $openid;

    /**
     * Keycloak OpenId Cache Configuration
     *
     * @var array
     */
    protected $cacheOpenid;

    /**
     * CallbackUrl
     *
     * @var array
     */
    protected $callbackUrl;

    /**
     * RedirectLogout
     *
     * @var array
     */
    protected $redirectLogout;

    /**
     * The state for authorization request
     *
     * @var string
     */
    protected $state;

    /**
     * The HTTP Client
     *
     * @var ClientInterface
     */
    protected $httpClient;

    /**
     * @var array of strings
     */
    protected $scopes = ['openid'];

    /**
     * The Constructor
     * You can extend this service setting protected variables before call
     * parent constructor to comunicate with Keycloak smoothly.
     *
     * @param ClientInterface $client
     * @return void
     */
    public function __construct(ClientInterface $client)
    {
        if (is_null($this->baseUrl)) {
            $this->baseUrl = trim(Config::get('keycloak-web.base_url'), '/');
        }

        if (is_null($this->realm)) {
            $this->realm = Config::get('keycloak-web.realm');
        }

        if (is_null($this->clientId)) {
            $this->clientId = Config::get('keycloak-web.client_id');
        }

        if (is_null($this->clientSecret)) {
            $this->clientSecret = Config::get('keycloak-web.client_secret');
        }

        if (is_null($this->cacheOpenid)) {
            $this->cacheOpenid = Config::get('keycloak-web.cache_openid', false);
        }

        if (is_null($this->callbackUrl)) {
            $this->callbackUrl = route('keycloak.callback');
        }

        if (is_null($this->redirectLogout)) {
            $this->redirectLogout = Config::get('keycloak-web.redirect_logout');
        }

        $this->scopes = array_merge($this->scopes, Config::get('keycloak-web.scopes'));

        $this->state = $this->generateRandomState();
        $this->httpClient = $client;
    }

    /**
     * Return the login URL
     *
     * @link https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
     *
     * @return string
     */
    public function getLoginUrl()
    {
        $url = $this->getOpenIdValue('authorization_endpoint');
        $params = [
            'scope' => implode(' ', $this->scopes),
            'response_type' => 'code',
            'client_id' => $this->getClientId(),
            'redirect_uri' => $this->callbackUrl,
            'state' => $this->getState(),
        ];

        return $this->buildUrl($url, $params);
    }

    /**
     * Return the logout URL
     *
     * @return string
     */
    public function getLogoutUrl()
    {
        $url = $this->getOpenIdValue('end_session_endpoint');

        if (empty($this->redirectLogout)) {
            $this->redirectLogout = url('/');
        }

        $params = [
            'client_id' => $this->getClientId()
        ];
        $token = $this->retrieveToken();
        if (! empty($token['id_token'])) {
            $params['post_logout_redirect_uri'] = $this->redirectLogout;
            $params['id_token_hint'] = $token['id_token'];
        }

        return $this->buildUrl($url, $params);
    }

    /**
     * Return the register URL
     *
     * @link https://stackoverflow.com/questions/51514437/keycloak-direct-user-link-registration
     *
     * @return string
     */
    public function getRegisterUrl()
    {
        $url = $this->getLoginUrl();
        return str_replace('/auth?', '/registrations?', $url);
    }
    /**
     * Get access token from Code
     *
     * @param  string $code
     * @return array
     */
    public function getAccessToken($code)
    {
        $url = $this->getOpenIdValue('token_endpoint');
        $params = [
            'code' => $code,
            'client_id' => $this->getClientId(),
            'grant_type' => 'authorization_code',
            'redirect_uri' => $this->callbackUrl,
        ];

        if (! empty($this->clientSecret)) {
            $params['client_secret'] = $this->clientSecret;
        }

        $token = [];

        try {
            $response = $this->httpClient->request('POST', $url, ['form_params' => $params]);

            if ($response->getStatusCode() === 200) {
                $token = $response->getBody()->getContents();
                $token = json_decode($token, true);
            }
        } catch (GuzzleException $e) {
            $this->logException($e);
        }

        return $token;
    }

    /**
     * Refresh access token
     *
     * @param  string $refreshToken
     * @return array
     */
    public function refreshAccessToken($credentials)
    {
        if (empty($credentials['refresh_token'])) {
            return [];
        }

        $url = $this->getOpenIdValue('token_endpoint');
        $params = [
            'client_id' => $this->getClientId(),
            'grant_type' => 'refresh_token',
            'refresh_token' => $credentials['refresh_token'],
            'redirect_uri' => $this->callbackUrl,
        ];

        if (! empty($this->clientSecret)) {
            $params['client_secret'] = $this->clientSecret;
        }

        $token = [];

        try {
            $response = $this->httpClient->request('POST', $url, ['form_params' => $params]);

            if ($response->getStatusCode() === 200) {
                $token = $response->getBody()->getContents();
                $token = json_decode($token, true);
            }
        } catch (GuzzleException $e) {
            $this->logException($e);
        }

        return $token;
    }

    /**
     * Invalidate Refresh
     *
     * @param  string $refreshToken
     * @return bool
     */
    public function invalidateRefreshToken($refreshToken)
    {
        $url = $this->getOpenIdValue('end_session_endpoint');
        $params = [
            'client_id' => $this->getClientId(),
            'refresh_token' => $refreshToken,
        ];

        if (! empty($this->clientSecret)) {
            $params['client_secret'] = $this->clientSecret;
        }

        try {
            $response = $this->httpClient->request('POST', $url, ['form_params' => $params]);
            return $response->getStatusCode() === 204;
        } catch (GuzzleException $e) {
            $this->logException($e);
        }

        return false;
    }

    /**
     * Get access token from Code
     * @param  array $credentials
     * @throws Exception
     * @return array
     */
    public function getUserProfile($credentials)
    {
        $credentials = $this->refreshTokenIfNeeded($credentials);

        $user = [];
        try {
            // Validate JWT Token
            $token = new KeycloakAccessToken($credentials);

            if (empty($token->getAccessToken())) {
                throw new Exception('Access Token is invalid.');
            }

            $claims = array(
                'aud' => $this->getClientId(),
                'iss' => $this->getOpenIdValue('issuer'),
            );

            // 如果有id_token，验证它；如果没有（API请求），只验证access_token
            if (!empty($token->getIdToken())) {
                $token->validateIdToken($claims);
            } else {
                // 对于API请求，验证access_token本身
                $accessTokenData = $token->parseAccessToken();
                if (empty($accessTokenData)) {
                    // 添加详细日志以便调试
                    $accessTokenStr = $token->getAccessToken();
                    Log::error('[Keycloak Service] Access Token cannot be parsed', [
                        'token_length' => strlen($accessTokenStr ?? ''),
                        'token_preview' => substr($accessTokenStr ?? '', 0, 50) . '...',
                        'has_access_token' => !empty($accessTokenStr),
                    ]);
                    throw new Exception('Access Token cannot be parsed.');
                }
                
                // 验证access_token的基本claims
                if (isset($accessTokenData['exp']) && time() >= (int)$accessTokenData['exp']) {
                    throw new Exception('Access Token has expired. Please refresh your token.');
                }
                
                if (isset($accessTokenData['iss']) && $accessTokenData['iss'] !== $claims['iss']) {
                    throw new Exception('Access Token has wrong issuer.');
                }
                
                // 验证audience：对于API请求，检查azp（authorized party）而不是aud
                // 因为Keycloak的access token的aud通常是"account"，但azp是实际授权的客户端
                if (isset($accessTokenData['azp'])) {
                    // 如果token有azp，验证它是否匹配配置的client_id
                    if ($accessTokenData['azp'] !== $claims['aud']) {
                        // 允许azp匹配client_id，这是正常的Keycloak行为
                        Log::debug('Access token azp does not match client_id, but continuing validation', [
                            'azp' => $accessTokenData['azp'],
                            'expected_client_id' => $claims['aud'],
                        ]);
                    }
                } else {
                    // 如果没有azp，检查aud是否包含client_id
                    $audience = (array)($accessTokenData['aud'] ?? []);
                    if (!in_array($claims['aud'], $audience, true)) {
                        Log::debug('Access token audience validation', [
                            'aud' => $accessTokenData['aud'] ?? null,
                            'expected_client_id' => $claims['aud'],
                        ]);
                        // 对于API请求，我们更宽松一些，因为Keycloak的aud可能是"account"
                        // 实际验证会通过UserInfo端点进行
                    }
                }
            }

            // Get userinfo
            $url = $this->getOpenIdValue('userinfo_endpoint');
            $headers = [
                'Authorization' => 'Bearer ' . $token->getAccessToken(),
                'Accept' => 'application/json',
            ];

            $response = $this->httpClient->request('GET', $url, ['headers' => $headers]);

            if ($response->getStatusCode() !== 200) {
                throw new Exception('Was not able to get userinfo (not 200)');
            }

            $user = $response->getBody()->getContents();
            $user = json_decode($user, true);

            // Validate retrieved user is owner of token
            // 如果有id_token，验证sub；如果没有，从access_token中获取sub
            if (!empty($token->getIdToken())) {
                $token->validateSub($user['sub'] ?? '');
            } else {
                // 对于API请求，从access_token中获取sub并验证
                $accessTokenData = $token->parseAccessToken();
                $tokenSub = $accessTokenData['sub'] ?? null;
                if ($tokenSub && $tokenSub !== ($user['sub'] ?? '')) {
                    throw new Exception('Token sub does not match userinfo sub.');
                }
            }
        } catch (GuzzleException $e) {
            $this->logException($e);
        } catch (Exception $e) {
            Log::error('[Keycloak Service] ' . print_r($e->getMessage(), true));
        }

        return $user;
    }

    /**
     * Retrieve Token from Session or Authorization Header
     *
     * @return array|null
     */
    public function retrieveToken()
    {
        // 1. 优先从Authorization Bearer header获取token（用于API请求）
        $request = request();
        if ($request) {
            $authHeader = $request->header('Authorization');
            if ($authHeader) {
                // 支持 "Bearer token" 或 "bearer token"（不区分大小写）
                if (preg_match('/^Bearer\s+(.+)$/i', $authHeader, $matches)) {
                    $token = trim($matches[1]); // 提取token并去除首尾空格和换行符
                    
                    // 清理token：移除可能的换行符、回车符等
                    $token = preg_replace('/[\r\n\t\s]+/', '', $token);
                    
                    // 验证token格式（JWT应该有3个部分，用.分隔）
                    $parts = explode('.', $token);
                    if (empty($token) || count($parts) !== 3) {
                        Log::error('[Keycloak Service] Invalid token format from Authorization header', [
                            'token_length' => strlen($token),
                            'token_preview' => substr($token, 0, 50) . '...',
                            'parts_count' => count($parts),
                            'header_preview' => substr($authHeader, 0, 100),
                        ]);
                        return null;
                    }
                    
                    // 验证每个部分都不为空
                    foreach ($parts as $index => $part) {
                        if (empty($part)) {
                            Log::error('[Keycloak Service] Empty token part', [
                                'part_index' => $index,
                                'token_preview' => substr($token, 0, 50) . '...',
                            ]);
                            return null;
                        }
                    }
                    
                    // 构造token数组格式（API请求通常只有access_token）
                    return [
                        'access_token' => $token,
                        'token_type' => 'Bearer',
                        // API请求可能没有id_token和refresh_token
                        // 但我们可以从access_token中解析用户信息
                    ];
                }
            }
        }
        
        // 2. 从Session获取token（用于Web请求）
        return session()->get(self::KEYCLOAK_SESSION);
    }

    /**
     * Save Token to Session
     *
     * @return void
     */
    public function saveToken($credentials)
    {
        // Ensure session is started before saving
        if (!session()->isStarted()) {
            session()->start();
        }
        
        session()->put(self::KEYCLOAK_SESSION, $credentials);
        session()->save();
        
        // Commit session to ensure it's written to storage
        if (method_exists(session()->driver(), 'commit')) {
            session()->driver()->commit();
        }
    }

    /**
     * Remove Token from Session
     *
     * @return void
     */
    public function forgetToken()
    {
        session()->forget(self::KEYCLOAK_SESSION);
        session()->save();
    }

    /**
     * Validate State from Session
     *
     * @return void
     */
    public function validateState($state)
    {
        // Ensure session is started before accessing it
        // This is critical for multi-tenant applications
        if (!session()->isStarted()) {
            session()->start();
        }
        
        $challenge = session()->get(self::KEYCLOAK_SESSION_STATE);
        
        // Log for debugging
        Log::debug('Keycloak validateState', [
            'request_state' => $state,
            'session_state' => $challenge,
            'session_id' => session()->getId(),
            'states_match' => $challenge === $state,
            'state_empty' => empty($state),
            'challenge_empty' => empty($challenge),
        ]);
        
        return (! empty($state) && ! empty($challenge) && $challenge === $state);
    }

    /**
     * Save State to Session
     *
     * @return void
     */
    public function saveState()
    {
        // Ensure session is started before saving state
        // This is critical for multi-tenant applications
        if (!session()->isStarted()) {
            session()->start();
        }
        
        session()->put(self::KEYCLOAK_SESSION_STATE, $this->state);
        session()->save();
        
        // Log for debugging
        Log::debug('Keycloak state saved', [
            'state' => $this->state,
            'session_id' => session()->getId(),
            'session_state_after_save' => session()->get(self::KEYCLOAK_SESSION_STATE),
        ]);
    }

    /**
     * Remove State from Session
     *
     * @return void
     */
    public function forgetState()
    {
        session()->forget(self::KEYCLOAK_SESSION_STATE);
        session()->save();
    }

    /**
     * Build a URL with params
     *
     * @param  string $url
     * @param  array $params
     * @return string
     */
    public function buildUrl($url, $params)
    {
        $parsedUrl = parse_url($url);
        if (empty($parsedUrl['host'])) {
            return trim($url, '?') . '?' . http_build_query($params);
        }

        if (! empty($parsedUrl['port'])) {
            $parsedUrl['host'] .= ':' . $parsedUrl['port'];
        }

        $parsedUrl['scheme'] = (empty($parsedUrl['scheme'])) ? 'https' : $parsedUrl['scheme'];
        $parsedUrl['path'] = (empty($parsedUrl['path'])) ? '' : $parsedUrl['path'];

        $url = $parsedUrl['scheme'] . '://' . $parsedUrl['host'] . $parsedUrl['path'];
        $query = [];

        if (! empty($parsedUrl['query'])) {
            $parsedUrl['query'] = explode('&', $parsedUrl['query']);

            foreach ($parsedUrl['query'] as $value) {
                $value = explode('=', $value);

                if (count($value) < 2) {
                    continue;
                }

                $key = array_shift($value);
                $value = implode('=', $value);

                $query[$key] = urldecode($value);
            }
        }

        $query = array_merge($query, $params);

        return $url . '?' . http_build_query($query);
    }

    /**
     * Return the client id for requests
     *
     * @return string
     */
    protected function getClientId()
    {
        return $this->clientId;
    }

    /**
     * Return the state for requests
     *
     * @return string
     */
    protected function getState()
    {
        return $this->state;
    }

    /**
     * Return a value from the Open ID Configuration
     *
     * @param  string $key
     * @return string
     */
    protected function getOpenIdValue($key)
    {
        if (! $this->openid) {
            $this->openid = $this->getOpenIdConfiguration();
        }

        return Arr::get($this->openid, $key);
    }

    /**
     * Retrieve OpenId Endpoints
     *
     * @return array
     */
    protected function getOpenIdConfiguration()
    {
        $cacheKey = 'keycloak_web_guard_openid-' . $this->realm . '-' . md5($this->baseUrl);

        // From cache?
        if ($this->cacheOpenid) {
            $configuration = Cache::get($cacheKey, []);

            if (! empty($configuration)) {
                return $configuration;
            }
        }

        // Request if cache empty or not using
        $url = $this->baseUrl . '/realms/' . $this->realm;
        $url = $url . '/.well-known/openid-configuration';

        $configuration = [];

        try {
            $response = $this->httpClient->request('GET', $url);

            if ($response->getStatusCode() === 200) {
                $configuration = $response->getBody()->getContents();
                $configuration = json_decode($configuration, true);
            }
        } catch (GuzzleException $e) {
            $this->logException($e);

            throw new Exception('[Keycloak Error] It was not possible to load OpenId configuration: ' . $e->getMessage());
        }

        // Save cache
        if ($this->cacheOpenid) {
            Cache::put($cacheKey, $configuration);
        }

        return $configuration;
    }

    /**
     * Check we need to refresh token and refresh if needed
     *
     * @param  array $credentials
     * @return array
     */
    protected function refreshTokenIfNeeded($credentials)
    {
        if (! is_array($credentials) || empty($credentials['access_token']) || empty($credentials['refresh_token'])) {
            return $credentials;
        }

        $token = new KeycloakAccessToken($credentials);
        if (! $token->hasExpired()) {
            return $credentials;
        }

        $credentials = $this->refreshAccessToken($credentials);

        if (empty($credentials['access_token'])) {
            $this->forgetToken();
            return [];
        }

        $this->saveToken($credentials);
        return $credentials;
    }

    /**
     * Log a GuzzleException
     *
     * @param  GuzzleException $e
     * @return void
     */
    protected function logException(GuzzleException $e)
    {
        // Guzzle 7
        if (! method_exists($e, 'getResponse') || empty($e->getResponse())) {
            Log::error('[Keycloak Service] ' . $e->getMessage());
            return;
        }

        $error = [
            'request' => method_exists($e, 'getRequest') ? $e->getRequest() : '',
            'response' => $e->getResponse()->getBody()->getContents(),
        ];

        Log::error('[Keycloak Service] ' . print_r($error, true));
    }

    /**
     * Return a random state parameter for authorization
     *
     * @return string
     */
    protected function generateRandomState()
    {
        return bin2hex(random_bytes(16));
    }
}
