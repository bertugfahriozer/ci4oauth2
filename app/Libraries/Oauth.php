<?php namespace App\Libraries;
/**
 *
 */
class Oauth
{
    /**
     * @var \OAuth2\Server
     */
    public $server;
    /**
     * @var \OAuth2\Storage\Pdo
     */
    protected $storage;

    /**
     * @param string $grantType
     * @param array $config
     */
    public function __construct(string $grantType='password', array $config=[])
    {
        $this->storage=new \App\Libraries\OauthPdoStorage(array(
            'client_table' => 'oauth_clients',
            'access_token_table' => 'oauth_access_tokens',
            'refresh_token_table' => 'oauth_refresh_tokens',
            'code_table' => 'oauth_authorization_codes',
            'user_table' => 'oauth_users',
            'jwt_table' => 'oauth_jwt',
            'jti_table' => 'oauth_jti',
            'scope_table' => 'oauth_scopes',
            'public_key_table' => 'oauth_public_keys',
        ));
        $this->server=new \OAuth2\Server($this->storage,$config);
        call_user_func_array([$this,$grantType],func_get_args());
    }

    /**
     * @return string
     */
    public function authorization_code()
    {
        $this->server->addGrantType(new \OAuth2\GrantType\AuthorizationCode($this->storage));
    }

    /**
     * @return string
     */
    public function password()
    {
        $this->server->addGrantType(new \OAuth2\GrantType\UserCredentials($this->storage));
    }

    /**
     * @return string
     */
    public function client_credentials()
    {
        $this->server->addGrantType(new \OAuth2\GrantType\ClientCredentials($this->storage));
    }

    /**
     * @return string
     */
    public function refresh_token()
    {
        $this->server->addGrantType(new \OAuth2\GrantType\RefreshToken($this->storage));
    }

    public function jwt_bearer()
    {
        $this->server->addGrantType(new \OAuth2\GrantType\JwtBearer($this->storage,'https://oauth'));
    }

    /**
     * Generate a JWT
     *
     * @param $privateKey The private key to use to sign the token
     * @param $iss The issuer, usually the client_id
     * @param $sub The subject, usually a user_id
     * @param $aud The audience, usually the URI for the oauth server
     * @param $exp The expiration date. If the current time is greater than the exp, the JWT is invalid
     * @param $nbf The "not before" time. If the current time is less than the nbf, the JWT is invalid
     * @param $jti The "jwt token identifier", or nonce for this JWT
     *
     * @return string
     */
    protected function generateJWT($privateKey, $iss, $sub, $aud, $exp = null, $nbf = null, $jti = null): string
    {
        if (!$exp) {
            $exp = time() + 1000;
        }

        $params = array(
            'iss' => $iss,
            'sub' => $sub,
            'aud' => $aud,
            'exp' => $exp,
            'iat' => time(),
        );

        if ($nbf) {
            $params['nbf'] = $nbf;
        }

        if ($jti) {
            $params['jti'] = $jti;
        }

        $jwtUtil = new \OAuth2\Encryption\Jwt();

        return $jwtUtil->encode($params, $privateKey, 'RS256');
    }

}