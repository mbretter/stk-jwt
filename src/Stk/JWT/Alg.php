<?php

namespace Stk\JWT;

use Closure;

class Alg
{
    /** @var string */
    protected $name;

    /** @var Closure */
    protected $hashFunc;

    /** @var Closure */
    protected $verifyFunc;

    /** @var Closure */
    protected $keygenFunc;

    public function __construct($name, Closure $keygenFunc, Closure $hashFunc, Closure $verifyFunc = null)
    {
        $this->name       = $name;
        $this->keygenFunc = $keygenFunc;
        $this->hashFunc   = $hashFunc;
        $this->verifyFunc = $verifyFunc;
    }

    public function sign($data, $secret)
    {
        return $this->hashFunc->call($this, $data, $secret);
    }

    public function verify($data, $secret, $sig)
    {
        if ($this->verifyFunc instanceof Closure) {
            return $this->verifyFunc->call($this, $data, $secret, $sig);
        }

        return hash_equals($this->sign($data, $secret), $sig);
    }

    /**
     * @param mixed $keyParam might be a keylength, curvename, etc
     *
     * @return mixed
     */
    public function genKey($keyParam = null)
    {
        return $this->keygenFunc->call($this, $keyParam);
    }

    public function getName()
    {
        return $this->name;
    }

}