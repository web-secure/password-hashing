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
 * The password hashing interface.
 */
interface Interface
{

    /**
     * Initialize the password hashing class.
     *
     * @param array $passwordHashingParams The password hashing parameters.
     *
     * @throws UnexpectedValueException If an unknown algo was passed.
     *
     * @return void.
     */
    public function __construct(array $passwordHashingParams = []);

    /**
     * Creates a password hash.
     *
     * @param string $password The password to hash.
     *
     * @throws InvalidArgumentException If the password is longer than 72 characters using bcrypt.
     *
     * @return string The hashed password.
     */
    public function create(string $password);

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
    public function verify(string $password, string $hash);
}
