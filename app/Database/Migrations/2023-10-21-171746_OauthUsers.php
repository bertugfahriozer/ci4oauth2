<?php

namespace ci4oauth2\Database\Migrations;

use CodeIgniter\Database\Migration;

class OauthUsers extends Migration
{
    public function up()
    {
        $this->forge->addField([
            'username' => [
                'type'           => 'varchar',
                'constraint'     => '80'
            ],
            'password' => [
                'type'           => 'varchar',
                'constraint'     => '80',
                'null'=>true
            ],
            'first_name' => [
                'type'           => 'varchar',
                'constraint'     => '80',
                'null'=>true
            ],
            'last_name' => [
                'type'           => 'varchar',
                'constraint'     => '80',
                'null'=>true
            ],
            'email' => [
                'type'           => 'varchar',
                'constraint'     => '80'
            ],
            'email_verified' => [
                'type'           => 'tinyint',
                'constraint'     => 1,
                'null'=>true
            ],
            'scope' => [
                'type'           => 'varchar',
                'constraint'     => '4000',
                'null'=>true
            ],
        ]);
        $this->forge->addKey('username', true);
        $this->forge->addKey('username', true);
        $this->forge->createTable('oauth_users');
    }

    public function down()
    {
        $this->forge->dropTable('oauth_users');
    }
}
