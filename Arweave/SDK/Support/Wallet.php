<?php

namespace Arweave\SDK\Support;
use Exception;
use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\RSA\Formats\Keys\JWK;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\RSAKey;

class Wallet
{
    const HASH = 'sha256';

    /**
     * Private key
     *
     * @var \phpseclib\Crypt\RSA
     */
    private $private;

    /**
     * @param array $jwk JWK as an array
     */
    public function __construct(array $jwk = [])
    {
        if (!$jwk) {
            throw new Exception('No key file specified');
        }

        $this->private = $this->RSAPrivateFromJWK($jwk);

        $this->owner = $jwk['n'];
        $this->address = static::ownerToAddress($this->owner);
    }

    private static function ownerToAddress(string $owner): string{
        return Helpers::base64urlEncode(base64_encode(hash('sha256', base64_decode(Helpers::base64urlDecode($owner)), true)));
    }

    /**
     * Get the wallet address.
     *
     * @return string Wallet address
     */
    public function getAddress(): string
    {
        return $this->address;
    }

    /**
     * Get the wallet owner (modulus).
     *
     * @return string Key modulus
     */
    public function getOwner(): string
    {
        return $this->owner;
    }

    /**
     * Sign the given message.
     *
     * @param  string $message Message to sign
     *
     * @return string Message signature
     */
    public function sign($message): string
    {
        return $this->private->sign($message);
    }

    private function RSAPrivateFromJWK(array $jwk): RSA
    {
        $key = RSA::load(json_encode($jwk), $password = false);

        $key = $key->withHash('sha256')->withMGFHash('sha256')->withSaltLength(0);
        if (!$key) {
            throw new Exception('Failed to read private RSA JWK');
        }

        return $key;
    }
}
