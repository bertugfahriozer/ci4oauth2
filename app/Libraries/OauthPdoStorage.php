<?php

namespace ci4oauth2\Libraries;

use OAuth2\OpenID\Storage\AuthorizationCodeInterface as OpenIDAuthorizationCodeInterface;
use OAuth2\OpenID\Storage\UserClaimsInterface;
use OAuth2\Storage\AccessTokenInterface;
use OAuth2\Storage\AuthorizationCodeInterface;
use OAuth2\Storage\ClientCredentialsInterface;
use OAuth2\Storage\JwtBearerInterface;
use OAuth2\Storage\PublicKeyInterface;
use OAuth2\Storage\RefreshTokenInterface;
use OAuth2\Storage\ScopeInterface;
use OAuth2\Storage\UserCredentialsInterface;
use ci4commonmodel\Models\CommonModel;

class OauthPdoStorage implements
    AuthorizationCodeInterface,
    AccessTokenInterface,
    ClientCredentialsInterface,
    UserCredentialsInterface,
    RefreshTokenInterface,
    JwtBearerInterface,
    ScopeInterface,
    PublicKeyInterface,
    UserClaimsInterface,
    OpenIDAuthorizationCodeInterface
{
    /**
     * @var array
     */
    protected $conf;

    protected $commonModel;

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

    /**
     * @param mixed $connection
     * @param array $config
     *
     * @throws InvalidArgumentException
     */
    public function __construct($config = array())
    {
        $this->conf = array_merge(array(
            'client_table' => 'oauth_clients',
            'access_token_table' => 'oauth_access_tokens',
            'refresh_token_table' => 'oauth_refresh_tokens',
            'code_table' => 'oauth_authorization_codes',
            'user_table' => 'oauth_users',
            'jwt_table' => 'oauth_jwt',
            'jti_table' => 'oauth_jti',
            'scope_table' => 'oauth_scopes',
            'public_key_table' => 'oauth_public_keys',
            'hashAlgorithm' => PASSWORD_DEFAULT,
            'hashMemoryCost' => 2048,
            'hashTimeCost' => 4,
            'hashThreads' => 4,
            'hashCost' => 10
        ), $config);
        $this->commonModel = new CommonModel();
    }

    /**
     * @param string $client_id
     * @param null|string $client_secret
     * @return bool
     */
    public function checkClientCredentials($client_id, $client_secret = null)
    {
        $result = $this->commonModel->selectOne($this->conf['client_table'], ['client_id' => $client_id], '*', '');

        // make this extensible
        return $result && $result->client_secret == $client_secret;
    }

    /**
     * @param string $client_id
     * @return bool
     */
    public function isPublicClient($client_id)
    {
        if (!$result = $this->commonModel->selectOne($this->conf['client_table'], ['client_id' => $client_id], '*', '')) {
            return false;
        }

        return empty($result->client_secret);
    }

    /**
     * @param string $client_id
     * @return array|mixed
     */
    public function getClientDetails($client_id)
    {
        return (array)$this->commonModel->selectOne($this->conf['client_table'], ['client_id' => $client_id], '*', '');
    }

    /**
     * @param string $client_id
     * @param null|string $client_secret
     * @param null|string $redirect_uri
     * @param null|array $grant_types
     * @param null|string $scope
     * @param null|string $user_id
     * @return bool
     */
    public function setClientDetails($client_id, $client_secret = null, $redirect_uri = null, $grant_types = null, $scope = null, $user_id = null)
    {
        // if it exists, update it.
        if ($this->getClientDetails($client_id)) {
            return $this->commonModel->edit($this->conf['client_table'], ['client_secret' => $client_secret, 'redirect_uri' => $redirect_uri, 'grant_types' => $grant_types, 'scope' => $scope, 'user_id' => $user_id], ['client_id' => $client_id]);
        } else {
            return $this->commonModel->create($this->conf['client_table'], ['client_id' => $client_id, 'client_secret' => $client_secret, 'redirect_uri' => $redirect_uri, 'grant_types' => $grant_types, 'scope' => $scope, 'user_id' => $user_id]);
        }
    }

    /**
     * @param $client_id
     * @param $grant_type
     * @return bool
     */
    public function checkRestrictedGrantType($client_id, $grant_type)
    {
        $details = $this->getClientDetails($client_id);
        if (isset($details->grant_types)) {
            $grant_types = explode(' ', $details->grant_types);

            return in_array($grant_type, (array)$grant_types);
        }

        // if grant_types are not defined, then none are restricted
        return true;
    }

    /**
     * @param string $access_token
     * @return array|bool|mixed|null
     */
    public function getAccessToken($access_token)
    {
        if ($token = $this->commonModel->selectOne($this->conf['access_token_table'], ['access_token' => $access_token], '*', '')) {
            // convert date string back to timestamp
            $token['expires'] = strtotime($token->expires);
        }

        return $token;
    }

    /**
     * @param string $access_token
     * @param mixed $client_id
     * @param mixed $user_id
     * @param int $expires
     * @param string $scope
     * @return bool
     */
    public function setAccessToken($access_token, $client_id, $user_id, $expires, $scope = null)
    {
        // convert expires to datestring
        $expires = date('Y-m-d H:i:s', $expires);

        // if it exists, update it.
        if ($this->getAccessToken($access_token)) {
            return $this->commonModel->edit($this->conf['access_token_table'], ['client_id' => $client_id, 'expires' => $expires, 'user_id' => $user_id, 'scope' => $scope], ['access_token' => $access_token]);
        } else {
            return $this->commonModel->create($this->conf['access_token_table'], ['access_token' => $access_token, 'client_id' => $client_id, 'expires' => $expires, 'user_id' => $user_id, 'scope' => $scope]);
        }
    }

    /**
     * @param $access_token
     * @return bool
     */
    public function unsetAccessToken($access_token)
    {
        $stmt = $this->db->prepare(sprintf('DELETE FROM %s WHERE access_token = :access_token', $this->conf['access_token_table']));

        $stmt->execute(compact('access_token'));

        return $stmt->rowCount() > 0;
    }

    /* OAuth2\Storage\AuthorizationCodeInterface */
    /**
     * @param string $code
     * @return mixed
     */
    public function getAuthorizationCode($code)
    {
        if ($code = $this->commonModel->selectOne($this->conf['code_table'], ['authorization_code' => $code], '*', '')) {
            // convert date string back to timestamp
            $code->expires = strtotime($code->expires);
        }

        return (array)$code;
    }

    /**
     * @param string $code
     * @param mixed $client_id
     * @param mixed $user_id
     * @param string $redirect_uri
     * @param int $expires
     * @param string $scope
     * @param string $id_token
     * @return bool|mixed
     */
    public function setAuthorizationCode($code, $client_id, $user_id, $redirect_uri, $expires, $scope = null, $id_token = null, $code_challenge = null, $code_challenge_method = null)
    {
        if (func_num_args() > 6) {
            // we are calling with an id token
            return call_user_func_array(array($this, 'setAuthorizationCodeWithIdToken'), func_get_args());
        }

        // convert expires to datestring
        $expires = date('Y-m-d H:i:s', $expires);

        // if it exists, update it.
        if ($this->getAuthorizationCode($code)) {
            return $this->commonModel->edit($this->conf['code_table'], ['client_id' => $client_id, 'user_id' => $user_id, 'redirect_uri' => $redirect_uri, 'expires' => $expires, 'scope' => $scope, 'code_challenge' => $code_challenge, 'code_challenge_method' => $code_challenge_method], ['authorization_code', $code]);
        } else {
            return $this->commonModel->create($this->conf['code_table'], ['authorization_code' => $code, 'client_id' => $client_id, 'user_id' => $user_id, 'redirect_uri' => $redirect_uri, 'expires' => $expires, 'scope' => $scope, 'code_challenge' => $code_challenge, 'code_challenge_method' => $code_challenge_method]);
        }
    }

    /**
     * @param string $code
     * @param mixed $client_id
     * @param mixed $user_id
     * @param string $redirect_uri
     * @param string $expires
     * @param string $scope
     * @param string $id_token
     * @return bool
     */
    private function setAuthorizationCodeWithIdToken($code, $client_id, $user_id, $redirect_uri, $expires, $scope = null, $id_token = null, $code_challenge = null, $code_challenge_method = null)
    {
        // convert expires to datestring
        $expires = date('Y-m-d H:i:s', $expires);
        // if it exists, update it.
        if ($this->getAuthorizationCode($code)) return $this->commonModel->edit($this->conf['code_table'], ['client_id' => $client_id, 'user_id' => $user_id, 'redirect_uri' => $redirect_uri, 'expires' => $expires, 'scope' => $scope, 'id_token' => $id_token, 'code_challenge' => $code_challenge, 'code_challenge_method' => $code_challenge_method], ['authorization_code' => $code]);
        else return $this->commonModel->create($this->conf['code_table'], ['authorization_code' => $code, 'client_id' => $client_id, 'user_id' => $user_id, 'redirect_uri' => $redirect_uri, 'expires' => $expires, 'scope' => $scope, 'id_token' => $id_token, 'code_challenge' => $code_challenge, 'code_challenge_method' => $code_challenge_method]);
    }

    /**
     * @param string $code
     * @return bool
     */
    public function expireAuthorizationCode($code)
    {
        return $this->commonModel->remove($this->conf['code_table'], ['authorization_code' => $code]);
    }

    /**
     * @param string $username
     * @param string $password
     * @return bool
     */
    public function checkUserCredentials($username, $password)
    {
        if ($user = $this->getUser($username)) {
            return $this->checkPassword((array)$user, $password);
        }

        return false;
    }

    /**
     * @param string $username
     * @return array|bool
     */
    public function getUserDetails($username)
    {
        return $this->getUser($username);
    }

    /**
     * @param mixed $user_id
     * @param string $claims
     * @return array|bool
     */
    public function getUserClaims($user_id, $claims)
    {
        if (!$userDetails = $this->getUserDetails($user_id)) {
            return false;
        }

        $claims = explode(' ', trim($claims));
        $userClaims = array();

        // for each requested claim, if the user has the claim, set it in the response
        $validClaims = explode(' ', self::VALID_CLAIMS);
        foreach ($validClaims as $validClaim) {
            if (in_array($validClaim, $claims)) {
                if ($validClaim == 'address') {
                    // address is an object with subfields
                    $userClaims['address'] = $this->getUserClaim($validClaim, $userDetails['address'] ?: $userDetails);
                } else {
                    $userClaims = array_merge($userClaims, $this->getUserClaim($validClaim, $userDetails));
                }
            }
        }

        return $userClaims;
    }

    /**
     * @param string $claim
     * @param array $userDetails
     * @return array
     */
    protected function getUserClaim($claim, $userDetails)
    {
        $userClaims = array();
        $claimValuesString = constant(sprintf('self::%s_CLAIM_VALUES', strtoupper($claim)));
        $claimValues = explode(' ', $claimValuesString);

        foreach ($claimValues as $value) {
            $userClaims[$value] = isset($userDetails[$value]) ? $userDetails[$value] : null;
        }

        return $userClaims;
    }

    /**
     * @param string $refresh_token
     * @return bool|mixed
     */
    public function getRefreshToken($refresh_token)
    {
        $token = $this->commonModel->selectOne($this->conf['refresh_token_table'], ['refresh_token' => $refresh_token], '*', '');
        // convert expires to epoch time
        $token->expires = strtotime($token->expires);
        return (array)$token;
    }

    /**
     * @param string $refresh_token
     * @param mixed $client_id
     * @param mixed $user_id
     * @param string $expires
     * @param string $scope
     * @return bool
     */
    public function setRefreshToken($refresh_token, $client_id, $user_id, $expires, $scope = null)
    {
        // convert expires to datestring
        $expires = date('Y-m-d H:i:s', $expires);
        return $this->commonModel->create($this->conf['refresh_token_table'], ['refresh_token' => $refresh_token, 'client_id' => $client_id, 'user_id' => $user_id, 'expires' => $expires, 'scope' => $scope]);
    }

    /**
     * @param string $refresh_token
     * @return bool
     */
    public function unsetRefreshToken($refresh_token)
    {
        return $this->commonModel->remove($this->conf['refresh_token_table'], ['refresh_token' => $refresh_token]);
    }

    /**
     * plaintext passwords are bad!  Override this for your application
     *
     * @param array $user
     * @param string $password
     * @return bool
     */
    protected function checkPassword($user, $password)
    {
        if(!password_verify(base64_encode(hash('sha384', $password, true)), $user['password'])) return false;
        if (password_needs_rehash($user['password'], $this->conf['hashAlgorithm'])) {
            $user['password'] = $password;
            $this->commonModel->edit($this->conf['user_table'], $user, ['username' => $user['user_id']]);
        }
        return $user['password'];
    }

    // use a secure hashing algorithm when storing passwords. Override this for your application
    protected function hashPassword($password)
    {
        if ((defined('PASSWORD_ARGON2I') && $this->conf['hashAlgorithm'] == PASSWORD_ARGON2I) || (defined('PASSWORD_ARGON2ID') && $this->conf['hashAlgorithm'] == PASSWORD_ARGON2ID))
            $hashOptions = ['memory_cost' => $this->conf['hashMemoryCost'], 'time_cost' => $this->conf['hashTimeCost'], 'threads' => $this->conf['hashThreads']];
        else $hashOptions = ['cost' => $this->conf['hashCost']];
        return password_hash(base64_encode(hash('sha384', $password, true)), $this->conf['hashAlgorithm'], $hashOptions);
    }

    /**
     * @param string $username
     * @return array|bool
     */
    public function getUser($username)
    {
        $result = $this->commonModel->selectOne($this->conf['user_table'], ['username' => $username], '*', '');
        if (!empty($result)) {
            $result->user_id = $result->username;
            return (array)$result;
        } else false;
    }

    /**
     * plaintext passwords are bad!  Override this for your application
     *
     * @param string $username
     * @param string $password
     * @param string $firstName
     * @param string $lastName
     * @return bool
     */
    public function setUser($username, $password, $firstName = null, $lastName = null)
    {
        // do not store in plaintext
        $password = $this->hashPassword($password);

        // if it exists, update it.
        if ($this->getUser($username)) return $this->commonModel->edit($this->conf['user_table'], ['password' => $password, 'first_name' => $firstName, 'last_name' => $lastName], ['username' => $username]);
        else return $this->commonModel->create($this->conf['user_table'], ['username' => $username, 'password' => $password, 'first_name' => $firstName, 'last_name' => $lastName]);
    }

    /**
     * @param string $scope
     * @return bool
     */
    public function scopeExists($scope)
    {
        $c = $this->commonModel->count($this->conf['scope_table'], ['scope' => $scope]);
        if ($c >= 0) return $c;
        return false;
    }

    /**
     * @param mixed $client_id
     * @return null|string
     */
    public function getDefaultScope($client_id = null)
    {
        if ($result = (array)$this->commonModel->selectOne($this->conf['scope_table'], ['is_default' => true], '*', '')) {
            $defaultScope = array_map(function ($row) {
                return $row['scope'];
            }, $result);

            return implode(' ', $defaultScope);
        }

        return null;
    }

    /**
     * @param mixed $client_id
     * @param $subject
     * @return string
     */
    public function getClientKey($client_id, $subject)
    {
        return (array)$this->commonModel->selectOne($this->conf['jwt_table'], ['cilient_id' => $client_id, 'subject' => $subject], 'public_key', '');
    }

    /**
     * @param mixed $client_id
     * @return bool|null
     */
    public function getClientScope($client_id)
    {
        if (!$clientDetails = $this->getClientDetails($client_id)) {
            return false;
        }

        if (isset($clientDetails['scope'])) {
            return $clientDetails['scope'];
        }

        return null;
    }

    /**
     * @param mixed $client_id
     * @param $subject
     * @param $audience
     * @param $expires
     * @param $jti
     * @return array|null
     */
    public function getJti($client_id, $subject, $audience, $expires, $jti)
    {
        if ($result = $this->commonModel->selectOne($this->conf['jti_table'], ['issuer' => $client_id, 'subject' => $subject, 'audience' => $audience, 'expires' => $expires, 'jti' => $jti], '*', '')) {
            return array(
                'issuer' => $result->issuer,
                'subject' => $result->subject,
                'audience' => $result->audience,
                'expires' => $result->expires,
                'jti' => $result->jti,
            );
        }

        return null;
    }

    /**
     * @param mixed $client_id
     * @param $subject
     * @param $audience
     * @param $expires
     * @param $jti
     * @return bool
     */
    public function setJti($client_id, $subject, $audience, $expires, $jti)
    {
        return $this->commonModel->create($this->conf['jti_table'], ['issuer' => $client_id, 'subject' => $subject, 'audience' => $audience, 'expires' => $expires, 'jti' => $jti]);
    }

    /**
     * @param mixed $client_id
     * @return mixed
     */
    public function getPublicKey($client_id = null)
    {
        $stmt = $this->db->prepare($sql = sprintf('SELECT public_key FROM %s WHERE client_id=:client_id OR client_id IS NULL ORDER BY client_id IS NOT NULL DESC', $this->conf['public_key_table']));

        $stmt->execute(compact('client_id'));
        if ($result = $stmt->fetch(\PDO::FETCH_ASSOC)) {
            return $result['public_key'];
        }
    }

    /**
     * @param mixed $client_id
     * @return mixed
     */
    public function getPrivateKey($client_id = null)
    {
        $stmt = $this->db->prepare($sql = sprintf('SELECT private_key FROM %s WHERE client_id=:client_id OR client_id IS NULL ORDER BY client_id IS NOT NULL DESC', $this->conf['public_key_table']));

        $stmt->execute(compact('client_id'));
        if ($result = $stmt->fetch(\PDO::FETCH_ASSOC)) {
            return $result['private_key'];
        }
    }

    /**
     * @param mixed $client_id
     * @return string
     */
    public function getEncryptionAlgorithm($client_id = null)
    {
        $stmt = $this->db->prepare($sql = sprintf('SELECT encryption_algorithm FROM %s WHERE client_id=:client_id OR client_id IS NULL ORDER BY client_id IS NOT NULL DESC', $this->conf['public_key_table']));

        $stmt->execute(compact('client_id'));
        if ($result = $stmt->fetch(\PDO::FETCH_ASSOC)) {
            return $result['encryption_algorithm'];
        }

        return 'RS256';
    }

    /**
     * DDL to create OAuth2 database and tables for PDO storage
     *
     * @see https://github.com/dsquier/oauth2-server-php-mysql
     *
     * @param string $dbName
     * @return string
     */
    public function getBuildSql($dbName = 'oauth2_server_php')
    {
        $sql = "
        CREATE TABLE {$this->conf['client_table']} (
          client_id             VARCHAR(80)   NOT NULL,
          client_secret         VARCHAR(80),
          redirect_uri          VARCHAR(2000),
          grant_types           VARCHAR(80),
          scope                 VARCHAR(4000),
          user_id               VARCHAR(80),
          PRIMARY KEY (client_id)
        );

            CREATE TABLE {$this->conf['access_token_table']} (
              access_token         VARCHAR(40)    NOT NULL,
              client_id            VARCHAR(80)    NOT NULL,
              user_id              VARCHAR(80),
              expires              TIMESTAMP      NOT NULL,
              scope                VARCHAR(4000),
              PRIMARY KEY (access_token)
            );

            CREATE TABLE {$this->conf['code_table']} (
              authorization_code  VARCHAR(40)    NOT NULL,
              client_id           VARCHAR(80)    NOT NULL,
              user_id             VARCHAR(80),
              redirect_uri        VARCHAR(2000),
              expires             TIMESTAMP      NOT NULL,
              scope               VARCHAR(4000),
              id_token            VARCHAR(1000),
              code_challenge        VARCHAR(1000),
              code_challenge_method VARCHAR(20),
              PRIMARY KEY (authorization_code)
            );

            CREATE TABLE {$this->conf['refresh_token_table']} (
              refresh_token       VARCHAR(40)    NOT NULL,
              client_id           VARCHAR(80)    NOT NULL,
              user_id             VARCHAR(80),
              expires             TIMESTAMP      NOT NULL,
              scope               VARCHAR(4000),
              PRIMARY KEY (refresh_token)
            );

            CREATE TABLE {$this->conf['user_table']} (
              username            VARCHAR(80),
              password            VARCHAR(80),
              first_name          VARCHAR(80),
              last_name           VARCHAR(80),
              email               VARCHAR(80),
              email_verified      BOOLEAN,
              scope               VARCHAR(4000)
            );

            CREATE TABLE {$this->conf['scope_table']} (
              scope               VARCHAR(80)  NOT NULL,
              is_default          BOOLEAN,
              PRIMARY KEY (scope)
            );

            CREATE TABLE {$this->conf['jwt_table']} (
              client_id           VARCHAR(80)   NOT NULL,
              subject             VARCHAR(80),
              public_key          VARCHAR(2000) NOT NULL
            );

            CREATE TABLE {$this->conf['jti_table']} (
              issuer              VARCHAR(80)   NOT NULL,
              subject             VARCHAR(80),
              audiance            VARCHAR(80),
              expires             TIMESTAMP     NOT NULL,
              jti                 VARCHAR(2000) NOT NULL
            );

            CREATE TABLE {$this->conf['public_key_table']} (
              client_id            VARCHAR(80),
              public_key           VARCHAR(2000),
              private_key          VARCHAR(2000),
              encryption_algorithm VARCHAR(100) DEFAULT 'RS256'
            )
        ";

        return $sql;
    }
}