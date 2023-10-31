<?php

namespace App\Controllers;

use App\Models\BlogModel;

class Blog extends BaseRestfull
{
    protected $model;

    public function __construct()
    {
        $this->model = new BlogModel();
    }

    public function index()
    {
        $limit=$this->request->getGet('limit');
        $page=0;
        if(!empty($this->request->getGet('p')) && $this->request->getGet('p')>1) $page=($this->request->getGet('p')-1)*15;
        $result=$this->model->findAll($limit,$page);
        if(empty($result)) return $this->respondNoContent();
        return $this->respond($result);
    }

    /**
     * Return the properties of a resource object
     *
     * @return mixed
     */
    public function show($id = null)
    {
        $result=$this->model->find($id);
        if(empty($result)) return $this->respondNoContent();
        return $this->respond($result);
    }

    /**
     * Create a new resource object, from "posted" parameters
     *
     * @return mixed
     */
    public function create()
    {
        $valData = (['blog_title' => ['rules' => 'required'], 'blog_content' => ['rules' => 'required']]);
        if ($this->validate($valData) == false) return $this->failValidationErrors($this->validator->getErrors());
        return $this->respondCreated(['result' => $this->model->save(['blog_title' => $this->request->getPost('blog_title'), 'blog_content' => $this->request->getPost('blog_content')])]);
    }

    /**
     * Add or update a model resource, from "posted" properties
     *
     * @return mixed
     */
    public function update($id = null)
    {
        $valData = (['blog_title' => ['rules' => 'required'], 'blog_content' => ['rules' => 'required']]);
        if ($this->validate($valData) == false) return $this->failValidationErrors($this->validator->getErrors());
        $infos=$this->model->find($id);
        if(empty($infos)) return $this->respondNoContent();
        return $this->respondUpdated(['result' => $this->model->update($id,$this->request->getRawInput())]);
    }

    /**
     * Delete the designated resource object from the model
     *
     * @return mixed
     */
    public function delete($id = null)
    {
        if($this->model->where(['id'=>$id])->countAllResults()==1) return $this->respondDeleted(['result' => $this->model->delete($id)]);
        return $this->respondNoContent();
    }
}
