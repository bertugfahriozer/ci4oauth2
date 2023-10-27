<?php

namespace App\Database\Seeds;

use App\Models\BlogModel;
use CodeIgniter\Database\Seeder;

class BlogSeeder extends Seeder
{
    public function run()
    {
        $faker= \Faker\Factory::create();
        $blogModel=new BlogModel();
        for ($i=0;$i<50;$i++){
            $blogModel->save([
               'blog_title' =>$faker->words(4,true),
               'blog_content'=>'<p>'.$faker->paragraphs(rand(5,10),true).'</p>'
            ]);
            echo $blogModel->db->getLastQuery()->getQuery();
        }
    }
}
