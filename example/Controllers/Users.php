<?php

namespace App\Controllers;

use CodeIgniter\RESTful\ResourceController;

class Users extends BaseRestfull
{
    public function index()
    {
        return $this->respond(['result'=>$this->commonModel->lists('oauth_users','*',[],'')]);
    }
}
