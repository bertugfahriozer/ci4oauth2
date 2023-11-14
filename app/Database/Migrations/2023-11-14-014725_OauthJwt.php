<?php

namespace ci4oauth2\Database\Migrations;

use CodeIgniter\Database\Migration;

class OauthJwt extends Migration
{
    public function up()
    {
        $this->forge->addField([
           'client_id' =>[
               'type'=>'VARCHAR',
               'constraint'=>80
           ],
            'subject' =>[
                'type'=>'VARCHAR',
                'constraint'=>80,
                'null'=>true
            ],
            'public_key' =>[
                'type'=>'VARCHAR',
                'constraint'=>2000
            ],
        ]);
        $this->forge->createTable('oauth_jwt');
    }

    public function down()
    {
        $this->forge->dropTable('oauth_jwt');
    }
}
