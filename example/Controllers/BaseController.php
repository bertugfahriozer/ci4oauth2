<?php

namespace App\Controllers;

use CodeIgniter\Controller;
use CodeIgniter\HTTP\CLIRequest;
use CodeIgniter\HTTP\IncomingRequest;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;
use ci4oauth2\Libraries\Oauth;
use Psr\Log\LoggerInterface;
use CodeIgniter\API\ResponseTrait;
use OAuth2\Request;

/**
 * Class BaseController
 *
 * BaseController provides a convenient place for loading components
 * and performing functions that are needed by all your controllers.
 * Extend this class in any new controllers:
 *     class Home extends BaseController
 *
 * For security be sure to declare any new methods as protected or private.
 */
abstract class BaseController extends Controller
{
    use ResponseTrait;
    /**
     * Instance of the main Request object.
     *
     * @var CLIRequest|IncomingRequest
     */
    protected $request;

    /**
     * An array of helpers to be loaded automatically upon
     * class instantiation. These helpers will be available
     * to all other controllers that extend BaseController.
     *
     * @var array
     */
    protected $helpers = [];
    public $respond;

    /**
     * Be sure to declare properties for any property fetch you initialized.
     * The creation of dynamic property is deprecated in PHP 8.2.
     */
    // protected $session;

    /**
     * @return void
     */
    public function initController(RequestInterface $request, ResponseInterface $response, LoggerInterface $logger)
    {
        // Do Not Edit This Line
        parent::initController($request, $response, $logger);

        // Preload any models, libraries, etc, here.

        // E.g.: $this->session = \Config\Services::session();
        $req = Request::createFromGlobals();

        //dd($this->config);
        $conf=['aud'=>'https://oauth'];
        if(empty($req->request) || empty($this->request->getPost('grant_type'))) {
            if($this->request->getPost('response_type')=='token') {
                $conf['allow_implicit'] = true;
                $oauth = new Oauth($this->request->getPost('response_type'), $conf);
            } if($this->request->getPost('response_type')=='code'){
                $oauth = new Oauth($this->request->getPost('response_type'));
            } else {
                $oauth = new Oauth();
            }
        }
        else {
            if($this->request->getPost('grant_type')=='refresh_token') $conf['always_issue_new_refresh_token'] = true;
            $oauth = new Oauth($this->request->getPost('grant_type'),$conf);
        }

        $this->respond = $oauth->server->handleTokenRequest($req);
    }
}
