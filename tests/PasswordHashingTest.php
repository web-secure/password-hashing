<?php
namespace Viper\PasswordHashing\Test;

use PHPUnit\Framework\TestCase;

class PasswordHashingTest extends TestCase
{
    public function testConstructor()
    {
        $options = [
            'algo' => 'bcrypt',
            'cost' => 10,
            'memory_cost' => \PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
            'time_cost' => \PASSWORD_ARGON2_DEFAULT_TIME_COST,
            'threads' => \PASSWORD_ARGON2_DEFAULT_THREADS,
        ];
        $passwordHasher = new \Viper\PasswordHashing($options);
        $this->assertTrue(\true);
        $options['algo'] = 'argon2i';
        $passwordHasher = new \Viper\PasswordHashing($options);
        $this->assertTrue(\true);
    }

    public function testBcryptError1()
    {
        $this->expectException(\InvalidArgumentException::class);
        $options = [
            'algo' => 'bcrypt',
            'cost' => 10,
        ];
        $passwordHasher = new \Viper\PasswordHashing($options);
        $hash = $passwordHasher->create('55ufbabm5&[-q=`_Br!~K.6NN<rXSsbLQ!A[cd>,"\'4\{5$!JmZupv_@A<R_Pc*m7:9-P{t">T.Q=u&s');
    }

    public function testBcryptError2()
    {
        $this->expectException(\InvalidArgumentException::class);
        $options = [
            'algo' => 'bcrypt',
            'cost' => 10,
        ];
        $passwordHasher = new \Viper\PasswordHashing($options);
        $hash = $passwordHasher->create('Hello World!');
    }

    public function testConstructorError1()
    {
        $this->expectException(\InvalidArgumentException::class);
        $options = [
            'algo' => 'other',
            'cost' => 10,
        ];
        $passwordHasher = new \Viper\PasswordHashing($options);
    }

    public function testPasswordCreateAndVerify()
    {
         $options = [
            'algo' => 'bcrypt',
            'cost' => 10,
        ];
        $passwordHasher = new \Viper\PasswordHashing($options);
        $this->assertTrue(\true);
        $hash = $passwordHasher->create('Hello World!');
        $this->assertTrue(\true);
        if ($passwordHasher->verify('Hello World!', $hash))
        {
            $this->assertTrue(\true);
        } else
        {
            $this->assertTrue(\false);
        }
        if ($passwordHasher->verify('Hello Tom!', $hash))
        {
            $this->assertTrue(\false);
        } else
        {
            $this->assertTrue(\true);
        }
        $options = [
            'algo' => 'bcrypt',
            'cost' => 15,
        ];
        $passwordHasher2 = new \Viper\PasswordHashing($options);
        $res = $passwordHasher2->verify('Hello World!', $hash);
        if (is_array($res))
        {
            $this->assertTrue(\true);
            $verifyNewHash = $res['hash'];
            if ($passwordHasher2->verify('Hello World!', $verifyNewHash))
            {
                $this->assertTrue(\true);
            } else
            {
                $this->assertTrue(\false);
            }
        } else
        {
            $this->assertTrue(\false);
        }
    }
}
