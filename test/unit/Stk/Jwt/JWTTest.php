<?php

namespace StkTest\Jwt;

use Stk\JWT\Header;
use Stk\JWT\JWT;
use Stk\JWT\Payload;

class JWTTest extends Base
{
    public function testWithHeader()
    {
        $jwt  = new JWT();
        $jwt2 = $jwt->withHeader(new Header(null, ['kid' => 2]));

        $this->assertNotSame($jwt, $jwt2);
        $this->assertEquals(2, $jwt2->getHeader('kid'));
    }

    public function testWithPayload()
    {
        $jwt  = new JWT();
        $jwt2 = $jwt->withPayload(new Payload(['sub' => 'foobar']));

        $this->assertNotSame($jwt, $jwt2);
        $this->assertEquals('foobar', $jwt2->getSubject());
    }

    public function testGetHeader()
    {
        $jwt = new JWT(new Header(null, ['typ' => 'JWT', 'cty' => 'json', 'kid' => 2, 'alg' => 'HS256']));

        $this->assertEquals('JWT', $jwt->getType());
        $this->assertEquals('json', $jwt->getContentType());
        $this->assertEquals(2, $jwt->getKid());
        $this->assertEquals('HS256', $jwt->getAlg());

        $this->assertEquals('JWT', $jwt->getHeader('typ'));
    }

    public function testGetClaim()
    {
        $jwt = new JWT(null, new Payload([
            'iss' => 'alice',
            'sub' => 'f3245609a',
            'aud' => 'bar.com',
            'iat' => 1579512134,
            'exp' => 1579512135,
            'nbf' => 1589512135,
            'jti' => '936DA01F-9ABD-4D9D-80C7-02AF85C822A8'
        ]));

        $this->assertEquals('alice', $jwt->getIssuer());
        $this->assertEquals('f3245609a', $jwt->getSubject());
        $this->assertEquals('bar.com', $jwt->getAudience());
        $this->assertEquals(1579512135, $jwt->getExpirationTime());
        $this->assertEquals(1589512135, $jwt->getNotBefore());
        $this->assertEquals(1579512134, $jwt->getIssuedAt());
        $this->assertEquals('936DA01F-9ABD-4D9D-80C7-02AF85C822A8', $jwt->getId());

        $this->assertEquals('f3245609a', $jwt->getClaim('sub'));
    }
}