<?php
declare(strict_types=1);
/**
 * WebSecure - PasswordHashing.
 * 
 * @author Nicholas English <https://github.com/iszorpal>.
 * @link <https://github.com/web-secure/password-hashing>.
 */

namespace WebSecure;

/**
 * The password hashing class.
 */
class PasswordHashing
{

    /** @var array $algo Contains links to the password hashing algos. */
    private $algo = [
        'bcrypt' => \PASSWORD_BCRYPT,
        'argon2i' => \PASSWORD_ARGON2I,
        'argon2id' => \PASSWORD_ARGON2ID
    ];

    /** @var array $options The options associated with the password hashing class. */
    private $options = [];

    /** @var array $hashOptions The password hash options. */
    private $hashOptions = [];

    /**
     * Initialize the password hashing class.
     *
     * @param array $passwordHashingParams The password hashing parameters.
     *
     * @throws UnexpectedValueException If an unkown algo was passed.
     *
     * @return void.
     */
    public function __construct(array $passwordHashingParams = [])
    {
        $resolver = new \Symfony\Component\OptionsResolver\OptionsResolver();
        $resolver->setDefaults([
            'algo' => 'bcrypt',
            'cost' => 10,
            'memory_cost' => \PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
            'time_cost' => \PASSWORD_ARGON2_DEFAULT_TIME_COST,
            'threads' => \PASSWORD_ARGON2_DEFAULT_THREADS,
        ]);
        $this->options = $resolver->resolve($passwordHashingParams);
        $this->options['algo'] = \strtolower($this->options['algo']);
        $algoConfirmed = \false;
        if ($this->options['algo'] == 'bcrypt') {
            $this->hashOptions = [
                'cost' => $this->options['cost']
            ];
            $algoConfirmed = \true;
        }
        if ($this->options['algo'] == 'argon2i' || $this->options['algo'] == 'argon2id') {
            $this->hashOptions = [
                'memory_cost' => $this->options['memory_cost'],
                'time_cost' => $this->options['time_cost'],
                'threads' => $this->options['threads']
            ];
            $algoConfirmed = \true;
        }
        if (!$algoConfirmed) {
            throw new \UnexpectedValueException('An unknown algo was passed.');
        }
    }

    /**
     * Creates a password hash.
     *
     * @param string $password The password to hash.
     *
     * @throws InvalidArgumentException If the password is longer than 72 characters using bcrypt.
     *
     * @return string The hashed password.
     */
    public function create(string $password)
    {
        if (\mb_strlen($password) > 72 && $this->options['algo'] == 'bcrypt') {
            throw new \InvalidArgumentException('Using BCRYPT the password can not be longer than 72 characters.');
        }
        return \password_hash($password, $this->algo[$this->options['algo']], $this->hashOptions);
    }

    /**
     * Verify that the password matches the given hash.
     *
     * @param string $password The password to check.
     * @param string $hash     The hash to check with.
     *
     * @throws InvalidArgumentException If the password is longer than 72 characters using bcrypt.
     *
     * @return mixed Returns true if the hash matches and does not require a rehash and false if it does not match, else 
     *               returns an array containing if the password matches the hash and the new hash to update it with.
     */
    public function verify(string $password, string $hash)
    {
        if (\mb_strlen($password) > 72 && $this->options['algo'] == 'bcrypt') {
            throw new \InvalidArgumentException('Using BCRYPT the password can not be longer than 72 characters.');
        }
        if (\password_verify($password, $hash)) {
            if (\password_needs_rehash($hash, $this->algo[$this->options['algo']], $this->hashOptions)) {
                $newHash = $this->create($password);
                return [
                    'verified' => \true,
                    'hash' => $newHash
                ];
            }
            return \true;
        }
        return \false;
    }
}
