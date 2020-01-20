<?php

namespace StkTest\Jwt;

use Stk\JWT\Payload;

class PayloadTest extends Base
{
    public function testWith()
    {
        $payload  = new Payload();
        $payload2 = $payload->with('sub', 'foobar');

        $this->assertNotSame($payload, $payload2);
        $this->assertEquals('foobar', $payload2->get('sub'));
    }

    public function testGet()
    {
        $payload = new Payload(['sub' => 'foobar']);
        $sub     = $payload->get('sub');

        $this->assertEquals('foobar', $sub);
    }

    public function testGetNotFound()
    {
        $header = new Payload();
        $sub    = $header->get('sub');

        $this->assertNull($sub);
    }
}