<?php

namespace ci4oauth2\Database\Migrations;

use CodeIgniter\Database\Migration;

class OauthAuthorizationCodes extends Migration
{
    public function up()
    {
        $this->forge->addField([
            'authorization_code' => [
                'type'           => 'varchar',
                'constraint'     => '40'
            ],
            'client_id' => [
                'type'       => 'varchar',
                'constraint' => '80',
            ],
            'user_id' => [
                'type' => 'varchar',
                'constraint' => '80',
                'null'=>true
            ],
            'redirect_uri' => [
                'type' => 'varchar',
                'constraint' => '2000',
                'null'=>true
            ],
            'expires' => [
                'type' => 'timestamp'
            ],
            'scope' => [
                'type' => 'varchar',
                'constraint' => '4000',
                'null'=>true
            ],
            'id_token' => [
                'type' => 'varchar',
                'constraint' => '1000',
                'null'=>true
            ],
        ]);
        $this->forge->addKey('authorization_code', true);
        $this->forge->addKey('authorization_code', true);
        $this->forge->createTable('oauth_authorization_codes');
    }

    public function down()
    {
        $this->forge->dropTable('oauth_authorization_codes');
    }
}
