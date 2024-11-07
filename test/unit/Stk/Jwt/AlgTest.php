<?php

namespace StkTest\Jwt;

use Stk\JWT\Algorithms;

class AlgTest extends Base
{
    public function testHS256KeyGen()
    {
        $alg = Algorithms::HS256();
        $key1 = $alg->genKey();
        $key2 = $alg->genKey();

        $this->assertNotEquals($key1, $key2);
        $this->assertEquals(32, strlen($key1));
    }

    public function testHS384KeyGen()
    {
        $alg = Algorithms::HS384();
        $key1 = $alg->genKey();
        $key2 = $alg->genKey();

        $this->assertNotEquals($key1, $key2);
        $this->assertEquals(48, strlen($key1));
    }

    public function testHS512KeyGen()
    {
        $alg = Algorithms::HS512();
        $key1 = $alg->genKey();
        $key2 = $alg->genKey();

        $this->assertNotEquals($key1, $key2);
        $this->assertEquals(64, strlen($key1));
    }

    public function testRS256KeyGen()
    {
        $alg = Algorithms::RS256();
        $key1 = $alg->genKey(2048);
        $key2 = $alg->genKey(2048);

        $this->assertNotEquals($key1, $key2);
        $this->assertStringStartsWith('-----BEGIN PRIVATE KEY-----', $key1);
    }

    public function testRS384KeyGen()
    {
        $alg = Algorithms::RS384();
        $key1 = $alg->genKey(2048);
        $key2 = $alg->genKey(2048);

        $this->assertNotEquals($key1, $key2);
        $this->assertStringStartsWith('-----BEGIN PRIVATE KEY-----', $key1);
    }

    public function testRS512KeyGen()
    {
        $alg = Algorithms::RS512();
        $key1 = $alg->genKey(2048);
        $key2 = $alg->genKey(2048);

        $this->assertNotEquals($key1, $key2);
        $this->assertStringStartsWith('-----BEGIN PRIVATE KEY-----', $key1);
    }

    public function testES256KeyGen()
    {
        $alg = Algorithms::ES256();
        $key1 = $alg->genKey();
        $key2 = $alg->genKey();

        $this->assertNotEquals($key1, $key2);
        $this->assertStringStartsWith('-----BEGIN PRIVATE KEY-----', $key1);
    }

    public function testES384KeyGen()
    {
        $alg = Algorithms::ES384();
        $key1 = $alg->genKey();
        $key2 = $alg->genKey();

        $this->assertNotEquals($key1, $key2);
        $this->assertStringStartsWith('-----BEGIN PRIVATE KEY-----', $key1);
    }

    public function testES512KeyGen()
    {
        $alg = Algorithms::ES512();
        $key1 = $alg->genKey();
        $key2 = $alg->genKey();

        $this->assertNotEquals($key1, $key2);
        $this->assertStringStartsWith('-----BEGIN PRIVATE KEY-----', $key1);
    }

    public function testDerivePublicKey()
    {
        $alg = Algorithms::RS256();
        $key = $alg->genKey();

        $pub = Algorithms::derivePublicKey($key);
        $this->assertStringStartsWith('-----BEGIN PUBLIC KEY-----', $pub);
    }

}