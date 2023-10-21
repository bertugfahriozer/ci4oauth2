<?php

namespace ci4oauth2\Database\Migrations;

use CodeIgniter\Database\Migration;

class OauthScopes extends Migration
{
    public function up()
    {
        $this->forge->addField([
            'scope' => [
                'type'           => 'varchar',
                'constraint'     => '80'
            ],
            'is_default' => [
                'type'       => 'tinyint',
                'constraint' => 1,
                'null'=>true
            ]
        ]);
        $this->forge->addKey('scope', true);
        $this->forge->addKey('scope', true);
        $this->forge->createTable('oauth_scopes');
    }

    public function down()
    {
        $this->forge->dropTable('oauth_scopes');
    }
}
