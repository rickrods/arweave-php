<?php

namespace Arweave\SDK\Tests;

use PHPUnit\Framework\TestCase;
use Arweave\SDK\Support\Wallet;
use Arweave\SDK\Support\Transaction;
use phpseclib3\Crypt\RSA;

class WalletTest extends TestCase
{
    private array $jwk;

    protected function setUp(): void
    {
        $privateKey = RSA::createKey(2048);
        $jwk = json_decode($privateKey->toString('JWK'), true);
        $this->jwk = $jwk['keys'][0] ?? $jwk;
    }

    public function testWalletInitialization(): void
    {
        $wallet = new Wallet($this->jwk);
        $this->assertEquals(43, strlen($wallet->getAddress()));
        $this->assertEquals($this->jwk['n'], $wallet->getOwner());
    }

    public function testTransactionSigningAndVerification(): void
    {
        $wallet = new Wallet($this->jwk);
        $tx = new Transaction([
            'owner' => $wallet->getOwner(),
            'data' => base64_encode('Unit Test')
        ]);

        $tx->sign($wallet);

        $this->assertNotEmpty($tx->getAttribute('signature'));
        $this->assertTrue($tx->verify());
    }
}