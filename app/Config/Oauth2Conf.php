<?php

namespace ci4oauth2\Config;

use CodeIgniter\Config\BaseConfig;

class Oauth2Conf extends BaseConfig
{
    public array $tables = ['client_table' => 'oauth_clients',
        'access_token_table' => 'oauth_access_tokens',
        'refresh_token_table' => 'oauth_refresh_tokens',
        'code_table' => 'oauth_authorization_codes',
        'user_table' => 'oauth_users',
        'jwt_table' => 'oauth_jwt',
        'jti_table' => 'oauth_jti',
        'scope_table' => 'oauth_scopes',
        'public_key_table' => 'oauth_public_keys'];

    public int $oauthFilterCap = 60;
    public int $rateLimitCap = 2;

    /* --------------------------------------------------------------------
     * Encryption Algorithm to use
     * --------------------------------------------------------------------
     * Valid values are
     * - PASSWORD_DEFAULT (default)
     * - PASSWORD_BCRYPT
     * - PASSWORD_ARGON2I  - As of PHP 7.2 only if compiled with support for it
     * - PASSWORD_ARGON2ID - As of PHP 7.3 only if compiled with support for it
     *
     * If you choose to use any ARGON algorithm, then you might want to
     * uncomment the "ARGON2i/D Algorithm" options to suit your needs
     */
    public $hashAlgorithm = PASSWORD_DEFAULT;
    public object $phpHashConfig = (object)[
        'hashMemoryCost' => 2048,
        'hashTimeCost' => 4,
        'hashThreads' => 4,
        'hashCost' => 10
    ];
}