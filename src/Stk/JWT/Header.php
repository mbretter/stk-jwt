<?php

namespace Stk\JWT;

use InvalidArgumentException;

class Header
{
    /** @var array */
    protected $headers = [];

    public function __construct(array $headers = [], string $alg = null)
    {
        $this->headers = $headers;

        // defaults to Hmac SHA 256
        if ($alg === null && !isset($this->headers['alg'])) {
            $this->headers['alg'] = 'HS256';
        }

        if ($alg !== null) {
            $this->headers['alg'] = $alg;
        }

    }

    /**
     * @param $str
     *
     * @return Header
     */
    public static function createFromJson($str)
    {
        $me          = new self;
        $me->headers = json_decode($str, true);
        if (!is_array($me->headers)) {
            throw new InvalidArgumentException('invalid json string');
        }

        return $me;
    }

    public function toJson()
    {
        $data = $this->headers;

        if (!isset($data['typ'])) {
            $data['typ'] = 'JWT';
        }

        return json_encode($data);
    }

    public function with($name, $val)
    {
        $me = clone($this);

        $me->headers[$name] = $val;

        return $me;
    }

    public function get($name)
    {
        if (!array_key_exists($name, $this->headers)) {
            return null;
        }

        return $this->headers[$name];
    }

}