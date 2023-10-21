<?php

namespace ci4oauth2\Database\Migrations;

use CodeIgniter\Database\Migration;

class OauthRefreshTokens extends Migration
{
    public function up()
    {
        $this->forge->addField([
            'refresh_token' => [
                'type' => 'varchar',
                'constraint' => '40',
            ],
            'client_id' => [
                'type' => 'varchar',
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
        $this->forge->addKey('refresh_token', true);
        $this->forge->addKey('refresh_token', true);
        $this->forge->createTable('oauth_refresh_tokens');
    }

    public function down()
    {
        $this->forge->dropTable('oauth_refresh_tokens');
    }
}
