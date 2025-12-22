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
        // Save state for logout callback validation
        KeycloakWeb::saveState();

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
            
            // Extract parameters from URL if provided (for Magento integration)
            $urlProjectId = $request->query('project_id');
            $urlTenantInstanceId = $request->query('tenant_instance_id');

            if ($urlProjectId && !session()->has('pending_project_id')) {
                session(['pending_project_id' => $urlProjectId]);
                Log::debug('Keycloak callback: Stored project_id from URL parameter', [
                    'project_id' => $urlProjectId,
                    'session_id' => session()->getId(),
                ]);
            }

            if ($urlTenantInstanceId && !session()->has('pending_tenant_instance_id')) {
                session(['pending_tenant_instance_id' => $urlTenantInstanceId]);
                Log::debug('Keycloak callback: Stored tenant_instance_id from URL parameter', [
                    'tenant_instance_id' => $urlTenantInstanceId,
                    'session_id' => session()->getId(),
                ]);
            }

            // Check if this is a Magento-initiated authentication
            $isFromMagento = session('from_magento_auth', false);
            $magentoCallbackUrl = session('magento_callback_url');

            // Try to get tenant for this user
            $result = $this->getOrCreateTenantForUser($userEmail, $userName);

            if (!$result || !is_array($result)) {
                Log::error('Keycloak callback: Failed to get or create tenant', [
                    'email' => $userEmail,
                    'result' => $result,
                ]);
                KeycloakWeb::forgetState();
                return redirect(route('keycloak.login'));
            }

            [$tenant, $isNewTenant] = $result;

            // Ensure current user exists in tenant, create if not exists
            $currentUser = Auth::guard($guardName)->user();
            if ($currentUser && $currentUser->email) {
                // Find the corresponding TenantUser
                $tenantUser = \App\Models\TenantUser::where('email', $currentUser->email)
                    ->where('tenant_id', $tenant->id)
                    ->first();

                if (!$tenantUser) {
                    // User doesn't exist in this tenant, create new user
                    $projectId = session('pending_project_id');
                    Log::info('Creating new tenant user for existing tenant', [
                        'user_email' => $currentUser->email,
                        'tenant_id' => $tenant->id,
                        'project_id' => $projectId,
                        'is_from_magento' => session('from_magento_auth'),
                        'session_id' => session()->getId(),
                    ]);

                    try {
                        // Create new tenant user
                        $tenantUser = \App\Models\TenantUser::create([
                            'tenant_id' => $tenant->id,
                            'email' => $currentUser->email,
                            'name' => $currentUser->name ?? $currentUser->email,
                            'password' => bcrypt(uniqid()), // Random password, user logs in via Keycloak
                            'project_id' => $projectId,
                        ]);

                        // Assign default role (you may want to customize this)
                        // For now, we'll skip role assignment as it might be complex
                        // $tenantUser->assignRole('member'); // Uncomment if you have roles set up

                        Log::info('New tenant user created successfully', [
                            'tenant_user_id' => $tenantUser->id,
                            'user_email' => $tenantUser->email,
                            'tenant_id' => $tenant->id,
                            'project_id' => $projectId,
                        ]);

                    } catch (\Exception $e) {
                        Log::error('Failed to create tenant user', [
                            'user_email' => $currentUser->email,
                            'tenant_id' => $tenant->id,
                            'error' => $e->getMessage(),
                        ]);
                        KeycloakWeb::forgetState();
                        return redirect(route('keycloak.login'));
                    }
                } else {
                    // User exists, update project_id if needed
                    if (empty($tenantUser->project_id)) {
                        $projectId = session('pending_project_id');
                        Log::info('Checking existing tenant user for project ID', [
                            'tenant_user_id' => $tenantUser->id,
                            'user_email' => $tenantUser->email,
                            'tenant_id' => $tenant->id,
                            'current_project_id' => $tenantUser->project_id,
                            'session_project_id' => $projectId,
                            'session_id' => session()->getId(),
                        ]);
                        if ($projectId) {
                            $tenantUser->update(['project_id' => $projectId]);
                            Log::info('Project ID set to existing tenant user', [
                                'tenant_user_id' => $tenantUser->id,
                                'user_email' => $tenantUser->email,
                                'tenant_id' => $tenant->id,
                                'project_id' => $projectId,
                            ]);
                        }
                    }
                }
            }
            
            // Check if this is a Magento-initiated authentication
            // If so, stay in Laravel backend instead of returning to Magento
            if ($isFromMagento) {
                $reason = $isNewTenant ? 'new tenant created' : 'user joined existing tenant';
                Log::info('Keycloak callback: Magento auth processed, staying in Laravel backend', [
                    'tenant_id' => $tenant->id,
                    'user_email' => $userEmail,
                    'is_new_tenant' => $isNewTenant,
                    'from_magento' => $isFromMagento,
                    'reason' => $reason,
                    'existing_tenant_id' => session('existing_tenant_id'),
                ]);

                // Clear Magento-related session data since we're not returning
                session()->forget(['from_magento_auth', 'magento_callback_url', 'existing_tenant_id']);
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
            
            // Clear panel context and Magento-related session data from session (no longer needed)
            session()->forget(['keycloak_panel_context', 'from_magento_auth', 'magento_callback_url', 'pending_project_id', 'pending_tenant_instance_id']);
            
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
     * @return array|null [tenant, is_new_tenant]
     */
    protected function getOrCreateTenantForUser(string $email, string $name)
    {
        try {
            // Check if there's an existing tenant ID from session (user joining existing tenant)
            $existingTenantId = session('existing_tenant_id');
            if ($existingTenantId && class_exists(\App\Models\Tenant::class)) {
                $existingTenant = \App\Models\Tenant::find($existingTenantId);
                if ($existingTenant) {
                    Log::debug('Keycloak callback: Found existing tenant from session', [
                        'email' => $email,
                        'tenant_id' => $existingTenantId,
                    ]);
                    return [$existingTenant, false]; // false = not new tenant, but new user in existing tenant
                }
            }

            // Check if tenant_user exists for this email
            if (class_exists(\App\Models\TenantUser::class)) {
                $tenantUser = \App\Models\TenantUser::where('email', $email)->first();

                if ($tenantUser && $tenantUser->tenant) {
                    Log::debug('Keycloak callback: Found existing tenant for user', [
                        'email' => $email,
                        'tenant_id' => $tenantUser->tenant_id,
                    ]);
                    return [$tenantUser->tenant, false]; // false = not new tenant
                }
            }
            
            // No tenant found, create a new tenant
            // 获取tenant_instance_id用于租户查找/创建
            $tenantInstanceId = session('pending_tenant_instance_id');

            Log::debug('Keycloak callback: Creating new tenant for user', [
                'email' => $email,
                'name' => $name,
                'tenant_instance_id' => $tenantInstanceId,
            ]);

            $tenant = $this->createTenantForUser($email, $name, $tenantInstanceId);
            return [$tenant, true]; // true = new tenant created
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
    protected function createTenantForUser(string $email, string $name, ?string $tenantInstanceId = null)
    {
        if (!class_exists(\App\Models\Tenant::class) || !class_exists(\App\Services\TenantPermissionService::class)) {
            Log::error('Keycloak callback: Required classes not found for tenant creation');
            return null;
        }
        
        return DB::transaction(function () use ($email, $name, $tenantInstanceId) {
            // 读取Project ID：优先从URL参数，其次从session
            $projectId = request('project_id') ?: session('pending_project_id');

            // 如果没有提供tenant_instance_id，从session获取
            if (!$tenantInstanceId) {
                $tenantInstanceId = session('pending_tenant_instance_id');
            }

            Log::info('Processing tenant creation/lookup', [
                'email' => $email,
                'project_id_from_url' => request('project_id'),
                'project_id_from_session' => session('pending_project_id'),
                'final_project_id' => $projectId,
                'tenant_instance_id_from_param' => $tenantInstanceId,
                'tenant_instance_id_from_session' => session('pending_tenant_instance_id'),
                'session_id' => session()->getId(),
            ]);

            // 检查是否已存在具有相同tenant_instance_id的租户
            $existingTenant = null;
            if ($tenantInstanceId && class_exists(\App\Models\Tenant::class)) {
                $existingTenant = \App\Models\Tenant::where('tenant_instance_id', $tenantInstanceId)->first();
                if ($existingTenant) {
                    Log::info('Found existing tenant with tenant_instance_id', [
                        'tenant_instance_id' => $tenantInstanceId,
                        'existing_tenant_id' => $existingTenant->id,
                        'existing_tenant_name' => $existingTenant->name,
                        'email' => $email,
                    ]);
                }
            }

            if ($existingTenant) {
                // 使用现有租户，只需要创建用户
                $tenant = $existingTenant;
                Log::info('Using existing tenant instead of creating new one', [
                    'tenant_id' => $tenant->id,
                    'tenant_instance_id' => $tenantInstanceId,
                    'email' => $email,
                ]);

                // 清理session
                session()->forget(['pending_project_id', 'pending_tenant_instance_id']);
            } else {
                // 生成唯一的tenant_instance_id（如果没有提供的话）
                if (!$tenantInstanceId) {
                    $tenantInstanceId = 'tenant-' . date('ymd') . '-' . substr(md5(uniqid()), 0, 6);
                }

                // Create tenant with tenant_instance_id
                $tenant = \App\Models\Tenant::create([
                    'name' => $name . ' Tenant',
                    'email' => $email,
                    'status' => 'active',
                    'tenant_instance_id' => $tenantInstanceId,
                ]);

                // 清理session（无论project_id来源，都清理session）
                session()->forget(['pending_project_id', 'pending_tenant_instance_id']);

                Log::info('Tenant created with tenant instance ID', [
                    'tenant_id' => $tenant->id,
                    'tenant_name' => $tenant->name,
                    'tenant_instance_id' => $tenantInstanceId,
                    'project_id' => $projectId,
                ]);
            }
            
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
            ], $projectId);

            Log::debug('Keycloak callback: Tenant admin user created', [
                'tenant_id' => $tenant->id,
                'admin_email' => $admin->email,
            ]);

            // Set the current tenant context for Filament
            \Filament\Facades\Filament::setTenant($tenant);

            Log::info('Filament tenant context set', [
                'tenant_id' => $tenant->id,
                'user_id' => $admin->id,
            ]);

            return $tenant;
        });
    }
}
