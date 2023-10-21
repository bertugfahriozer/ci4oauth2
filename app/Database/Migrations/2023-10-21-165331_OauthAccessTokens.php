<?php

namespace ci4oauth2\Database\Migrations;

use CodeIgniter\Database\Migration;

class OauthAccessTokens extends Migration
{
    public function up()
    {
        $this->forge->addField([
            'access_token' => [
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
            'expires' => [
                'type' => 'timestamp'
            ],
            'scope' => [
                'type' => 'varchar',
                'constraint' => '4000',
                'null'=>true
            ],
        ]);
        $this->forge->addKey('access_token', true);
        $this->forge->addKey('access_token', true);
        $this->forge->createTable('oauth_access_tokens');
    }

    public function down()
    {
        $this->forge->dropTable('oauth_access_tokens');
    }
}
