<?php namespace App\Controllers;

use ci4oauth2\Libraries\OauthPdoStorage;

class Home extends BaseController
{
    public function index()
    {
        echo uniqid();
        return view('welcome_message');
    }

    public function login()
    {
        return $this->respond(json_decode($this->respond->getResponseBody()), $this->respond->getStatusCode());
    }

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
        $oauth = new OauthPdoStorage();
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
        $oauth = new OauthPdoStorage();
        $result = $oauth->setUser($this->request->getPost('username'), $this->request->getPost('password'));
        if ($result === 0) return $this->respondCreated(['result' => 'user created']);
        else if ($result === true) return $this->respondUpdated(['result' => 'user updated.']);
        else return $this->failServerError();
    }

    public function token()
    {
        return $this->respond(json_decode($this->respond->getResponseBody()), $this->respond->getStatusCode());
    }

    public function genjwt()
    {
        $private_key = file_get_contents(ROOTPATH . 'jwtRS256.key');
        $client_id = 'testbertug';
        $user_id = 'bertutest';
        helper('oauth');
        $jwt = generateJWT($private_key, $client_id, $user_id, 'https://oauth');
        return $jwt;
    }
}
