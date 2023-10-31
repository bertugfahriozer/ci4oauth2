<?php

namespace ci4oauth2\Filters;

use CodeIgniter\Filters\FilterInterface;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;
use Config\Services;

class RateLimit implements FilterInterface
{
    /**
     * This is a demo implementation of using the Throttler class
     * to implement rate limiting for your application.
     *
     * @param array|null $arguments
     *
     * @return mixed
     */
    public function before(RequestInterface $request, $arguments = null)
    {
        if (Services::throttler()->check(md5($request->getIPAddress()), config('Oauth2Conf')->rateLimitCap, MINUTE) === false)
            return Services::response()->setContentType('application/json')->setStatusCode(429)->setJSON(['error'=>'Too Many Requests','error_description'=>'You can send requests '.config('Oauth2Conf')->rateLimitCap.' times in a minute !']);
    }

    /**
     * We don't have anything to do here.
     *
     * @param array|null $arguments
     *
     * @return mixed
     */
    public function after(RequestInterface $request, ResponseInterface $response, $arguments = null)
    {
        // ...
    }
}