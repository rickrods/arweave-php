<?php
// This script automatically generates an RSA key pair, initializes a wallet, signs a transaction,
// and verifies the cryptographic signature using phpseclib 3.x.

require_once __DIR__ . '../../vendor/autoload.php';

use Arweave\SDK\Arweave;
use Arweave\SDK\Support\Wallet;
use Arweave\SDK\Support\Transaction;
use phpseclib3\Crypt\RSA;

echo "==================================================\n";
echo "  Testing Modernized arweave-php Library\n";
echo "==================================================\n\n";

$passed = 0;
$failed = 0;

function assertTest(string $description, bool $condition) {
    global $passed, $failed;
    if ($condition) {
        echo " [PASS] " . $description . "\n";
        $passed++;
    } else {
        echo " [FAIL] " . $description . "\n";
        $failed++;
    }
}

try {
    // 1. Generate dynamic test JWK using phpseclib3
    echo "1. Generating test RSA JWK Key...\n";
    $privateKey = RSA::createKey(2048);
    $jwk = json_decode($privateKey->toString('JWK'), true);
    if (isset($jwk['keys'][0])) {
        $jwk = $jwk['keys'][0];
    }

    // 2. Test Wallet Class
    echo "\n2. Testing Wallet Initialization...\n";
    $wallet = new Wallet($jwk);
    
    assertTest("Wallet address generated successfully", !empty($wallet->getAddress()));
    assertTest("Wallet owner (modulus) matches JWK", $wallet->getOwner() === $jwk['n']);
    assertTest("Wallet address length is valid base64url (43 chars)", strlen($wallet->getAddress()) === 43);

    // 3. Test Transaction Creation & Signing
    echo "\n3. Testing Transaction Creation & RSA-PSS Signing...\n";
    $arweave = new Arweave('https', 'arweave.net', 443);
    
    $tx = new Transaction([
        'last_tx' => 'nQoflnhlpZwYuSHVQGYGTo41WR8MxBFfF9DNNbApoIp',
        'owner'   => $wallet->getOwner(),
        'target'  => 'nQoflnhlpZwYuSHVQGYGTo41WR8MxBFfF9DNNbApoIp',
        'quantity'=> '100',
        'data'    => base64_encode('Hello Arweave Modernization!'),
        'tags'    => []
    ]);
    
    $tx->addTag('App-Name', 'Modernization-Test');
    $tx->sign($wallet);

    assertTest("Transaction signature generated", !empty($tx->getAttribute('signature')));
    assertTest("Transaction ID generated (43 chars)", strlen($tx->getAttribute('id')) === 43);

    // 4. Test Signature Verification (verify())
    echo "\n4. Testing Cryptographic Verification...\n";
    $isValid = $tx->verify();
    assertTest("Valid transaction signature verification returns TRUE", $isValid === true);

    // 5. Test Tamper Detection
    echo "\n5. Testing Tamper Security...\n";
    // Clone transaction and modify data to simulate tampered payload
    $tamperedTx = new Transaction(array_merge($tx->getAttributes(), [
        'quantity' => '99999999' // Modified quantity
    ]));
    
    $tamperedValid = $tamperedTx->verify();
    assertTest("Tampered transaction verification returns FALSE", $tamperedValid === false);

    // 6. Test Live Network Gateway Read (No funds spent)
    echo "\n6. Testing Network Gateway Read (arweave.net)...\n";
    $anchor = $arweave->api()->getTransactionAnchor();
    assertTest("Retrieved network transaction anchor", !empty($anchor) && is_string($anchor));

} catch (Exception $e) {
    echo "\n [ERROR] Exception caught: " . $e->getMessage() . "\n";
    echo $e->getTraceAsString() . "\n";
    $failed++;
}

echo "\n==================================================\n";
echo "Test Results: {$passed} Passed, {$failed} Failed\n";
echo "==================================================\n";

exit($failed > 0 ? 1 : 0);