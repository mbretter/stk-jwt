<?php

namespace StkTest\Jwt;

use Stk\JWT\Algorithms;
use Stk\JWT\Header;

class HeaderTest extends Base
{
    public function testWith()
    {
        $header  = new Header();
        $header2 = $header->with('kid', 2);

        $this->assertNotSame($header, $header2);
        $this->assertEquals(2, $header2->get('kid'));
    }

    public function testGet()
    {
        $header = new Header(Algorithms::HS256()->getName(), ['kid' => 3]);
        $kid    = $header->get('kid');

        $this->assertEquals(3, $kid);
    }

    public function testGetNotFound()
    {
        $header = new Header();
        $kid    = $header->get('kid');

        $this->assertNull($kid);
    }
}