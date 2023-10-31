<?php

namespace ci4oauth2\Filters;

use ci4oauth2\Libraries\Oauth;
use CodeIgniter\Filters\FilterInterface;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;
use Config\Services;
use OAuth2\Request;

class OauthFilter implements FilterInterface
{
    /**
     * Do whatever processing this filter needs to do.
     * By default it should not return anything during
     * normal execution. However, when an abnormal state
     * is found, it should return an instance of
     * CodeIgniter\HTTP\Response. If it does, script
     * execution will end and that Response will be
     * sent back to the client, allowing for error pages,
     * redirects, etc.
     *
     * @param RequestInterface $request
     * @param array|null       $arguments
     *
     * @return mixed
     */
    public function before(RequestInterface $request, $arguments = null)
    {
        if (Services::throttler()->check(base64_encode($request->getIPAddress()), config('Oauth2Conf')->oauthFilterCap, MINUTE) === false)
            return Services::response()->setContentType('application/json')->setStatusCode(429)->setJSON(['error'=>'Too Many Requests.You must wait 10 seconds !']);

        $oauth = new Oauth();
        $request = Request::createFromGlobals();
        if(!$oauth->server->verifyResourceRequest($request)) die($oauth->server->getResponse()->send());
    }

    /**
     * Allows After filters to inspect and modify the response
     * object as needed. This method does not allow any way
     * to stop execution of other after filters, short of
     * throwing an Exception or Error.
     *
     * @param RequestInterface  $request
     * @param ResponseInterface $response
     * @param array|null        $arguments
     *
     * @return mixed
     */
    public function after(RequestInterface $request, ResponseInterface $response, $arguments = null)
    {
        //
    }
}
