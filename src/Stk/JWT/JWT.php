<?php

namespace Stk\JWT;

use InvalidArgumentException;
use RuntimeException;
use stdClass;

/**
 * Class JWT
 *
 * @see https://tools.ietf.org/html/rfc7519
 *
 * @package Stk\JWT
 */
class JWT
{
    /** @var Header */
    protected $header;

    /** @var Payload */
    protected $payload;

    /**
     * JWT constructor.
     *
     * @param Header $header
     * @param Payload $payload
     */
    public function __construct(Header $header = null, Payload $payload = null)
    {
        if ($header === null) {
            $header = new Header();
        }

        if ($payload === null) {
            $payload = new Payload();
        }

        $this->header  = $header;
        $this->payload = $payload;
    }

    public function withHeader(Header $header)
    {
        $me         = clone($this);
        $me->header = $header;

        return $me;
    }

    public function withPayload(Payload $payload)
    {
        $me          = clone($this);
        $me->payload = $payload;

        return $me;
    }


    /**
     * @param mixed $secretKey secret, privateKey
     * @param Alg|null $alg
     *
     * @return string
     */
    public function sign($secretKey, Alg $alg = null)
    {
        if ($alg === null) {
            $alg = Algorithms::HS256();
        }

        $hashData = sprintf(
            '%s.%s',
            self::b64UrlEncode($this->header->toJson()),
            self::b64UrlEncode($this->payload->toJson())
        );

        $sig = self::b64UrlEncode($alg->sign($hashData, $secretKey));

        return sprintf('%s.%s', $hashData, $sig);
    }

    /**
     * @param $token
     * @param $secretKey
     * @param Alg|null $alg
     *
     * @return bool|mixed
     */
    public static function verify($token, $secretKey, Alg $alg = null)
    {
        if ($alg === null) {
            $alg = Algorithms::HS256();
        }

        $parts = self::getParts($token);
        if ($parts === false) {
            throw new InvalidArgumentException('invalid token format');
        }

        $jwt = new self(
            Header::createFromJson(self::b64UrlDecode($parts->header)),
            Payload::createFromJson(self::b64UrlDecode($parts->payload))
        );

        $hashData = sprintf('%s.%s', $parts->header, $parts->payload);

        if (!$alg->verify($hashData, $secretKey, self::b64UrlDecode($parts->signature))) {
            throw new RuntimeException('invalid signature');
        }

        return $jwt;
    }

    // headers

    public function getType()
    {
        return $this->getHeader('typ');
    }

    public function getContentType()
    {
        return $this->getHeader('cty');
    }

    /**
     * do not rely on the alg header field when verifying, this might be forged
     *
     * @return mixed|null
     */
    public function getAlg()
    {
        return $this->getHeader('alg');
    }

    // generic

    public function getHeader($name)
    {
        return $this->header->get($name);
    }

    // claims

    public function getIssuer()
    {
        return $this->getClaim('iss');
    }

    public function getSubject()
    {
        return $this->getClaim('sub');
    }

    public function getAudience()
    {
        return $this->getClaim('aud');
    }

    public function getExpirationTime()
    {
        return $this->getClaim('exp');
    }

    public function getNotBefore()
    {
        return $this->getClaim('nbf');
    }

    public function getIssuedAt()
    {
        return $this->getClaim('iat');
    }

    public function getId()
    {
        return $this->getClaim('jti');
    }

    // generic

    public function getClaim($name)
    {
        return $this->payload->get($name);
    }

    // helper

    /**
     * @param $token
     *
     * @return bool|stdClass
     */
    public static function getParts($token)
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return false;
        }

        $ret            = new stdClass();
        $ret->header    = $parts[0];
        $ret->payload   = $parts[1];
        $ret->signature = $parts[2];

        return $ret;
    }


    /**
     * @param $data
     *
     * @return string
     */
    protected static function b64UrlEncode($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * @param $data
     *
     * @return bool|string
     */
    protected static function b64UrlDecode($data)
    {
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
    }
}
