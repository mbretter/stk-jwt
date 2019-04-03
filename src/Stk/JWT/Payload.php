<?php

namespace Stk\JWT;

use InvalidArgumentException;

class Payload
{
    protected $claims = [];

    public function __construct(array $claims = [])
    {
        $this->claims = $claims;
    }

    public static function createFromJson($str)
    {
        $me         = new self;
        $me->claims = json_decode($str, true);
        if (!is_array($me->claims)) {
            throw new InvalidArgumentException('invalid json string');
        }

        return new self(json_decode($str, true));
    }

    public function toJson()
    {
        return json_encode($this->claims);
    }

    public function with($name, $val)
    {
        $me = clone($this);

        $me->claims[$name] = $val;

        return $me;
    }

    public function get($name)
    {
        if (!array_key_exists($name, $this->claims)) {
            return null;
        }

        return $this->claims[$name];
    }
}