<?php
namespace Viper\PasswordHashing\Test;

use PHPUnit\Framework\TestCase;

class PasswordHashingTest extends TestCase
{
    public function testConstructor()
    {
        $options = [
            'algo' => 'bcrypt',
            'bcrypt_cost' => 10,
            'argon_memory_cost' => \PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
            'argon_time_cost' => \PASSWORD_ARGON2_DEFAULT_TIME_COST,
            'argon_threads' => \PASSWORD_ARGON2_DEFAULT_THREADS,
        ];
        $passwordHasher = new \Viper\PasswordHashing($options);
        $this->assertTrue(true);
        $options['algo'] = 'argon2i';
        $passwordHasher = new \Viper\PasswordHashing($options);
        $this->assertTrue(true);
        // Constructor works!
    }
}
