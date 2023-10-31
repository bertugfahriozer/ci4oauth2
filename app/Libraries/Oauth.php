<?php namespace ci4oauth2\Libraries;
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

    protected $conf;

    /**
     * @param string $grantType
     * @param array $config
     */
    public function __construct(string $grantType='password', array $config=[])
    {
        $this->storage=new \ci4oauth2\Libraries\OauthPdoStorage();
        $this->server=new \OAuth2\Server($this->storage,$config);
        if(strpos($grantType, "grant-type:jwt-bearer")) $grantType='jwt_bearer';
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
        $this->server->addGrantType(new \OAuth2\GrantType\JwtBearer($this->storage,$this->conf['aud']));
    }
}