<table>
  <tr>
    <th style="width:50%;">English</th>
    <th style="width:50%;">Türkçe</th>
  </tr>
<tr>
   <td style="width:50%;">

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
   - [Configuration](#configuration)
- [Authorization Types](#authorization-types)
   - [Authorization Code](#authorization-code)
   - [Client Credentials](#client-credentials)
   - [User Credentials](#user-credentials)
   - [Refresh Token](#refresh-token)
   - [JWT Bearer](#jwt-bearer)
     - [JWT Preparation](#jwt-preparation)
- [Contribution](#contribution)
- [License](#license)
</td>
   <td style="width:50%;">

- [Özellikler](#özellikler)
- [Kurulum](#kurulum)
- [Kullanım](#kullanım)
   - [Ayarlar](#ayarlar)
   - [Örnek Kullanım](#örnek-kullanım)
- [Yetkilendirme Türleri](#yetkilendirme-türleri)
   - [Authorization Code (Yetkilendirme Kodu veri türü)](#authorization-code-yetkilendirme-kodu-veri-türü)
   - [Client Credentials (İstemci Kimlik Bilgileri)](#client-credentials-i̇stemci-kimlik-bilgileri)
   - [Kullanıcı Kimlik Bilgileri (User Credentials)](#kullanıcı-kimlik-bilgileri-user-credentials)
   - [Jetonu Yenile (Refresh Token)](#jetonu-yenile-refresh-token)
   - [JWT Taşıyıcı (JWT Bearer)](#jwt-taşıyıcı-jwt-bearer)
     - [JWT Hazırlanışı](#jwt-hazırlanışı)
- [Katkıda Bulunma](#katkıda-bulunma)
- [Lisans](#lisans)
</td>
</tr>
</table>

# Codeigniter 4 OAuth2 Library

This is an OAuth2 library that can be used in CodeIgniter 4. It allows users to authorize and authenticate with
third-party applications.

## Features

- Easily configure and deploy an OAuth2 server application.
- Support for authorizing and authenticating users with third-party applications.
- Integration with any client application that supports the OAuth2 protocol.
- Access authorization mechanisms that secure user capabilities.

## Installation

To add the library to your project, follow these steps:

1. Navigate to your project's files.

2. Use Composer to add the library to your project with the following command:

   `composer require bertugfahriozer/ci4oauth2`

3. To create the required database tables, run the following command:
4. 
   `php spark migrate -all`

4. You'll need to create a configuration file. To create a config file, run the following command:

   `php spark make:config`

5. You're now ready to use the OAuth2 library in your project!

## Usage

### Configuration

Here's an example of a configuration file you can create for your OAuth2 library:

```php
<?php namespace App\Config

class Oauth2Conf extends BaseConfig
{
   public $config = [
      'always_issue_new_refresh_token' => true,
      'refresh_token_lifetime' => 2592000
   ];
}
```

The example above is a sample config file created for the Refresh Token method.

Usage example of the OAuth2 library:

```php
<?php

namespace App\Controllers;

use CodeIgniter\Controller;
use ci4oauth2\Libraries\Oauth;

class AuthController extends Controller {
private $oauth;
private $respond;

    public function __construct() {
        $config = config('Oauth2Conf');

        $oauth = new Oauth($this->request->getPost('grant_type'), $config);
        $this->respond = $oauth->server->handleTokenRequest($req);
    }

    public function authorize() {
        return $this->respond(json_decode($this->respond->getResponseBody()), $this->respond->getStatusCode());
    }
}
```

Here are sample methods for creating users in the database:

```php
public function createclient() {
   $vald = [
      'client_id' => ['label' => '', 'rules' => 'required'],
      'client_secret' => ['label' => '', 'rules' => 'required'],
      'redirect_url' => ['label' => '', 'rules' => 'required|valid_url'],
      'grant_types' => ['label' => '', 'rules' => 'required'],
   ];
   if (strpos($this->request->getPost('grant_types'), "password")) {
      $vald['username'] = ['label' => '', 'rules' => 'required'];
      $vald['password'] = ['label' => '', 'rules' => 'required'];
   }
   $valData = ($vald);
   if ($this->validate($valData) == false) return $this->failValidationErrors($this->validator->getErrors());
   $oauth = new \ci4oauth2\Libraries\OauthPdoStorage();
   $result = $oauth->setClientDetails($this->request->getPost('client_id'), $this->request->getPost('client_secret'), $this->request->getPost('redirect_url'), $this->request->getPost('grant_types'));
   if ($result === 0) return $this->respondCreated(['result' => 'client created']);
   else if ($result === true) return $this->respondUpdated(['result' => 'client updated.']);
   else return $this->failServerError();
}

public function createuser() {
   $valData = ([
      'username' => ['label' => '', 'rules' => 'required'],
      'password' => ['label' => '', 'rules' => 'required']
   ]);
   if ($this->validate($valData) == false) return $this->failValidationErrors($this->validator->getErrors());
   $oauth = new \ci4oauth2\Libraries\OauthPdoStorage();
   $result = $oauth->setUser($this->request->getPost('username'), $this->request->getPost('password'));
   if ($result === 0) return $this->respondCreated(['result' => 'user created']);
   else if ($result === true) return $this->respondUpdated(['result' => 'user updated.']);
   else return $this->failServerError();
}
```

## Authorization Types

### Authorization Code

The authorization code grant type is used when the client wants to request access to protected resources on behalf of
another user (i.e., a third-party user). This is the most commonly associated data type with
OAuth. [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1)

#### Example Request

`curl --location 'https://oauth/authorize' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'grant_type=authorization_code' \
--data-urlencode 'client_id=testclient' \
--data-urlencode 'redirect_uri=http://oauth/' \
--data-urlencode 'code=xyz' \
--data-urlencode 'client_secret=testpass'`

#### Result

`{ "access_token": "794b60b710a9d9128387d1dc7920484cf32080c6", "expires_in": 3600, "token_type": "Bearer", "scope": null, "refresh_token": "fa7f4a30f7861047a9a3c130d197b8d708bc0fa3" }`

### Client Credentials

The Client Credentials grant type is used when the client is requesting access to protected resources under its
control (i.e. there is no third party). [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4)

#### Example Request

`curl --location 'https://oauth/authorize' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'grant_type=client_credentials' \
--data-urlencode 'client_id=testbertug' \
--data-urlencode 'client_secret=passbertug'`

#### Result

`{ "access_token": "33d85a1a68ad617add7f66cd7855e532738c3d84", "expires_in": 3600, "token_type": "Bearer", "scope": null }`

### User Credentials

The User Credentials grant type (also known as Resource Owner Password Credentials) is used when the user has a trusted
relationship with the client, and so can supply credentials
directly. [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749#section-4.3)

#### Example Request

`curl --location 'https://oauth/authorize' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'grant_type=password' \
--data-urlencode 'username=testbertug' \
--data-urlencode 'password=testpass' \
--data-urlencode 'client_id=testbertug' \
--data-urlencode 'client_secret=passbertug'`

#### Result

`{ "access_token": "557118343a9f7642804cdeef124195be437eb9c2", "expires_in": 3600, "token_type": "Bearer", "scope": null, "refresh_token": "308c5f9b3b91cdc233b64550e13baa287efa3eea" }`

### Refresh Token

The Refresh Token grant type is used to obtain additional access tokens in order to prolong the client's authorization
of a user's resources. [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749#section-1.5)

#### Example Request

`curl --location 'https://oauth/authorize' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'grant_type=refresh_token' \
--data-urlencode 'refresh_token=afd5ab42392fd24fe3dc8b0f88c4505b4841d64a' \
--data-urlencode 'client_id=testbertug' \
--data-urlencode 'client_secret=passbertug'`

#### Result

`{ "access_token": "7e0c0ed74a06f21c5c0e3d75a086f6c7306113b2", "expires_in": 3600, "token_type": "Bearer", "scope": null }`

### JWT Bearer

The JWT Bearer grant type is used when the client wants to receive access tokens without transmitting sensitive
information such as the client secret. This can also be used with trusted clients to gain access to user resources
without user authorization. [RFC 7523](https://datatracker.ietf.org/doc/html/rfc7523)

#### JWT Preparation

To prepare JWTs, SSL keys should be created in advance and shared with the server where the requests will be made, or a
panel should be set up to process the data. Here's an example of creating an SSL:

```
// private key
$ openssl genrsa -out privatekey.pem 2048

// public key
$ openssl rsa -in privkey.pem -pubout -out publickey.pem
```

A code example to generate a JWT:

```php
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
  function generateJWT($privateKey, $iss, $sub, $aud, $exp = null, $nbf = null, $jti = null) {
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
   
     $jwtUtil = new OAuth2\Encryption\Jwt();
   
     return $jwtUtil->encode($params, $privateKey, 'RS256');
  }
```

#### Example Request

`curl --location 'http://oauth/authorize' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer' \
--data-urlencode 'assertion=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ0ZXN0Y2xpZW50Iiwic3viIjoiYmVydHVnIiwiYXVkIjoiaHR0cHM6XC9cL29hdXRoXC90b2tlbiIsImV4cCI6MTY5Nzk0MzA0NywiaWF0IjoxNjk3OTQyMDQ3fQ.zOAR0P4M1MUfNC3Ptn_yuu3YJEwkTl503_RFCGU3omd2HNc12NAWxlZ9hXFr4-T5ymfizWix1hwNcqnBfyO69_ugsHK2G9x5zfzrTfr3cTk592LGWIE6zVhbr2ybmCStz_oocDqBrAO_aQcY0SMFOgqyQPb2OIx_z2rpBmCSdgpaiNB1f0eFbtwlFcbk_IQ9VjU-pvqVaOdWYCjUV690q3gztASBbqzRpqlEVvh9SdHe700e5eGdefW4gept11VN9i8EL5JuiQJYT0ptOfQbzqJ3N534FLFn56Zg77D2i9yFsAckLZpyyKQCSM-G_-4Jjsamm0fuEANiRDK25PRPF82DRnTOoW09N4z6h5pmk82oibGsqpyjEEmVyT5_UVoAwvKmjvsEMp2L46BM9C4bAm5qdjk_GWZcH_mr98wmfbkNDZ6cPegMMoIVz13yUHBp3VFDYb0EpigqWj6-fBDOxn7__a9S2qIlD6n3Uhg5MxI5HmwB-mrCJ-_CJ2m0hETaW94-KzcN23BUgk5CAdUkwMfndtW8nCmd3MXObo2b_rK8bJlhl_XH87xeGGY7DVb8t1vQnEd0-aonN790qSIt3Bsuzsa7kNEo_YVIu14gcae_9vzN2qn_ZUbzs8xO9t8WEq28M6VdU0xtdnvcq9HobFnIwaRpgsrGTjSOciw2nU'`

#### Result

`{ "access_token": "093440df45a567699c0e797d3c0641b3d1977e36", "expires_in": 3600, "token_type": "Bearer", "scope": null }`

This is just a basic usage example, and you can expand it according to the specific requirements of your project.

## Contribution

If you have any issues or requests related to this library on GitHub, please report them using the GitHub issue tracker.
If you'd like to contribute to the project, please submit a pull request.

## License

This library is licensed under the [MIT License](https://opensource.org/licenses/MIT).

<hr>

# Codeigniter 4 OAuth2 Kütüphanesi

Bu, CodeIgniter 4’te kullanılabilen bir OAuth2 kütüphanesidir. Kullanıcıların, üçüncü taraf uygulamalara yetkilendirme
ve kimlik doğrulama yapabilmelerini sağlar.

## Özellikler

- Oauth2 sunucu uygulamasını kolayca yapılandırma ve dağıtma
- Kullanıcılar için üçüncü taraf uygulamalarla yetkilendirme ve kimlik doğrulama desteği
- OAuth2 protokolünü destekleyen herhangi bir istemci uygulaması ile entegre olma
- Kullanıcıların yeteneklerini güvence altına alan erişim yetkilendirme mekanizmaları

## Kurulum

Kütüphaneyi projenize eklemek için şu adımları izleyin:

1. Projeye ait dosyalara gidin.

2. Composer kullanarak kütüphaneyi projeye eklemek için şu komutu çalıştırın:

   ```php
   composer require bertugfahriozer/ci4oauth2
   ```

3. Gerekli veritabanı tablolarını oluşturmak için aşağıdaki komutu çalıştırın:

    ```php
    php spark migrate -all
    ```

4. Bir adet config dosyasına ihtiyacınız olacak. Config dosyası oluşturmak için aşağıdaki komutu çalıştırın:

    ```php
   php spark make:config
   ```

5. Artık OAuth2 kütüphanesi projenizde kullanımak için temelleri hazır!

## Kullanım

### Ayarlar

Oluşturduğunu Config dosyası için örnek:

```php
<?php namespace App\Config

class Oauth2Conf extends BaseConfig
{
    public $config = [
        'always_issue_new_refresh_token' => true,
        'refresh_token_lifetime' => 2592000
    ];
}
```

Yukarıda yazılmış olan Refresh Token metodu için oluşturulmuş örnek bir config dosyasıdır.

Kullanılan OAuth2.0 metoduna göre değişiklik gösterebilir.

### Örnek Kullanım

Aşağıda, kütüphanenin kullanımına ilişkin basit bir örnek bulunmaktadır:

```php
<?php

namespace App\Controllers;

use CodeIgniter\Controller;
use ci4oauth2\Libraries\Oauth;

class AuthController extends Controller
{
    private $oauth;
    private $respond;

    public function __construct()
    {
        $config = config('Oauth2Conf');

        $oauth = new Oauth($this->request->getPost('grant_type'),$config);
        $this->respond = $oauth->server->handleTokenRequest($req);
    }

    public function authorize()
    {
        return $this->respond(json_decode($this->respond->getResponseBody()), $this->respond->getStatusCode());
    }
}
```

Kullanıcıları veritabanında oluşturmak için örnek metotlar şu şekildedir:

```php
public function createclient()
    {
        $vald = [
            'client_id' => ['label' => '', 'rules' => 'required'],
            'client_secret' => ['label' => '', 'rules' => 'required'],
            'redirect_url' => ['label' => '', 'rules' => 'required|valid_url'],
            'grant_types' => ['label' => '', 'rules' => 'required'],
        ];
        if (strpos($this->request->getPost('grant_types'), "password")) {
            $vald['username'] = ['label' => '', 'rules' => 'required'];
            $vald['password'] = ['label' => '', 'rules' => 'required'];
        }
        $valData = ($vald);
        if ($this->validate($valData) == false) return $this->failValidationErrors($this->validator->getErrors());
        $oauth = new \ci4oauth2\Libraries\OauthPdoStorage();
        $result = $oauth->setClientDetails($this->request->getPost('client_id'), $this->request->getPost('client_secret'), $this->request->getPost('redirect_url'), $this->request->getPost('grant_types'));
        if ($result === 0) return $this->respondCreated(['result' => 'client created']);
        else if ($result === true) return $this->respondUpdated(['result' => 'client updated.']);
        else return $this->failServerError();
    }

    public function createuser()
    {
        $valData = ([
            'username' => ['label' => '', 'rules' => 'required'],
            'password' => ['label' => '', 'rules' => 'required']
        ]);
        if ($this->validate($valData) == false) return $this->failValidationErrors($this->validator->getErrors());
        $oauth = new \ci4oauth2\Libraries\OauthPdoStorage();
        $result = $oauth->setUser($this->request->getPost('username'), $this->request->getPost('password'));
        if ($result === 0) return $this->respondCreated(['result' => 'user created']);
        else if ($result === true) return $this->respondUpdated(['result' => 'user updated.']);
        else return $this->failServerError();
    }
```

## Yetkilendirme Türleri

### Authorization Code (Yetkilendirme Kodu veri türü)

istemcinin başka bir kullanıcı adına (yani 3. taraf bir kullanıcı adına) korumalı kaynaklara erişim talep etmek
istediğinde kullanılır. Bu, genellikle OAuth ile en çok ilişkilendirilen veri
türüdür. [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1)

#### Örnek İstek

```php
curl --location 'https://oauth/authorize' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'grant_type=authorization_code' \
--data-urlencode 'client_id=testclient' \
--data-urlencode 'redirect_uri=http://oauth/' \
--data-urlencode 'code=xyz' \
--data-urlencode 'client_secret=testpass'
```

#### Sonuç

```
{ "access_token": "794b60b710a9d9128387d1dc7920484cf32080c6", "expires_in": 3600, "token_type": "Bearer", "scope": null, "refresh_token": "fa7f4a30f7861047a9a3c130d197b8d708bc0fa3" }
```

### Client Credentials (İstemci Kimlik Bilgileri)

İstemci Kimlik Bilgileri yetkilendirme türü, istemcinin denetimi altındaki korumalı kaynaklara erişim talep ettiği
durumlarda kullanılır (yani üçüncü bir taraf
bulunmaz). [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4)

#### Örnek İstek

```php
curl --location 'https://oauth/authorize' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'grant_type=client_credentials' \
--data-urlencode 'client_id=testbertug' \
--data-urlencode 'client_secret=passbertug'
```

#### Sonuç

```
{ "access_token": "33d85a1a68ad617add7f66cd7855e532738c3d84", "expires_in": 3600, "token_type": "Bearer", "scope": null }
```

### Kullanıcı Kimlik Bilgileri (User Credentials)

Kullanıcı Kimlik Bilgileri yetkilendirme türü (diğer adıyla Kaynak Sahibi Parola Kimlik Bilgileri), kullanıcının istemci
ile güvenilir bir ilişkisi olduğu ve bu nedenle kimlik bilgilerini doğrudan sağlayabildiği durumlarda
kullanılır. [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749#section-4.3)

#### Örnek İstek

```php
curl --location 'https://oauth/authorize' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'grant_type=password' \
--data-urlencode 'username=testbertug' \
--data-urlencode 'password=testpass' \
--data-urlencode 'client_id=testbertug' \
--data-urlencode 'client_secret=passbertug'
```

#### Sonuç

```
{ "access_token": "557118343a9f7642804cdeef124195be437eb9c2", "expires_in": 3600, "token_type": "Bearer", "scope": null, "refresh_token": "308c5f9b3b91cdc233b64550e13baa287efa3eea" }
```

### Jetonu Yenile (Refresh Token)

Yenileme Jetonu yetkilendirme türü, istemcinin kullanıcının kaynaklarına verdiği yetkiyi uzatmak amacıyla ek erişim
jetonları elde etmek için kullanılır. [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749#section-1.5)

#### Örnek İstek

```php
curl --location 'https://oauth/authorize' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'grant_type=refresh_token' \
--data-urlencode 'refresh_token=afd5ab42392fd24fe3dc8b0f88c4505b4841d64a' \
--data-urlencode 'client_id=testbertug' \
--data-urlencode 'client_secret=passbertug'
```

#### Sonuç

```
{ "access_token": "7e0c0ed74a06f21c5c0e3d75a086f6c7306113b2", "expires_in": 3600, "token_type": "Bearer", "scope": null }
```

### JWT Taşıyıcı (JWT Bearer)

JWT Taşıyıcı yetkilendirme türü, istemcinin hassas bilgileri (örneğin, istemci sırrı) iletmeksizin erişim jetonları
almak istediğinde kullanılır. Bu, güvendiğiniz istemcilerle kullanıcı onayı olmadan kullanıcı kaynaklarına erişmek için
de kullanılabilir. [RFC 7523](https://datatracker.ietf.org/doc/html/rfc7523)

#### JWT Hazırlanışı

Önceden hazırlanmış ssl keyleri istek atacağınız sunucu için paylaşılmalı veya panel hazırlanıp verilerin işlenmesi
istenilmeli. Örnek SSL üretelim:

```php
// private key
$ openssl genrsa -out privatekey.pem 2048

// public key
$ openssl rsa -in privkey.pem -pubout -out publickey.pem
```

örnek olarak JWT üretmek için kod:

```php
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
function generateJWT($privateKey, $iss, $sub, $aud, $exp = null, $nbf = null, $jti = null)
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

    $jwtUtil = new OAuth2\Encryption\Jwt();

    return $jwtUtil->encode($params, $privateKey, 'RS256');
}
```

#### Örnek İstek

```php
curl --location 'http://oauth/authorize' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer' \
--data-urlencode 'assertion=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ0ZXN0Y2xpZW50Iiwic3ViIjoiYmVydHVnIiwiYXVkIjoiaHR0cHM6XC9cL29hdXRoXC90b2tlbiIsImV4cCI6MTY5Nzk0MzA0NywiaWF0IjoxNjk3OTQyMDQ3fQ.zOAR0P4M1MUfNC3Ptn_yuu3YJEwkTl503_RFCGU3omd2HNc12NAWxlZ9hXFr4-T5ymfizWix1hwNcqnBfyO69_ugsHK2G9x5zfzrTfr3cTk592LGWIE6zVhbr2ybmCStz_oocDqBrAO_aQcY0SMFOgqyQPb2OIx_z2rpBmCSdgpaiNB1f0eFbtwlFcbk_IQ9VjU-pvqVaOdWYCjUV690q3gztASBbqzRpqlEVvh9pSdHe700e5eGdefW4gept11VN9i8EL5JuiQJYT0ptOfQbzqJ3N534FLFn56Zg77D2i9yFsAckLZpyyKQCSM-G_-4Jjsamm0fuEANiRDK25PRPF82DRnTOoW09N4z6h5pmk82oibGsqpyjEEmVyT5_UVoAwvKmjvsEMp2L46BM9C4bAm5qdjk_GWZcH_mr98wmfbkNDZ6cPegMMoIVz13yUHBp3VFDYb0EpigqWj6-fBDOxn7__a9S2qIlD6n3Uhg5MxI5HmwB-mrCJ-_CJ2m0hETaW94-KzcN23BUgk5CAdUkwMfndtW8nCmd3MXObo2b_rK8bJlhl_XH87xeGGY7DVb8t1vQnEd0-aonN790qSIt3Bsuzsa7kNEo_YVIu14gcae_9vzN2qn_ZUbzs8xO9t8WEq28M6VdU0xtdnvcq9HobFnIwaRpgsrGTjSOciw2nU'
```

#### Sonuç

```
{ "access_token": "093440df45a567699c0e797d3c0641b3d1977e36", "expires_in": 3600, "token_type": "Bearer", "scope": null }
```

Bu sadece temel bir kullanım örneği olup, projenize özgü gereksinimlere göre genişletebilirsiniz.

## Katkıda Bulunma

Eğer GitHub üzerinde bulunan bu kütüphane hakkında bir sorununuz veya isteğiniz varsa, lütfen GitHub sorun takipçisini
kullanarak bildirin. Ayrıca, projeye katkıda bulunmak isterseniz, lütfen bir “pull request” gönderin.

## Lisans

Bu kütüphane,  [MIT Lisansı](https://opensource.org/licenses/MIT)  ile lisanslanmıştır.