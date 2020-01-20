<?php

namespace Stk\JWT;

use Exception;
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
     * verify the token, return false on error
     *
     * @param string $token
     * @param $secretKey
     * @param Alg|null $alg
     *
     * @return bool|static
     */
    public static function validate($token, $secretKey, Alg $alg = null)
    {
        try {
            return self::verify($token, $secretKey, $alg);
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * verify the token, throw exception on error
     *
     * @param string $token
     * @param $secretKey
     * @param Alg|null $alg
     *
     * @return static
     * @throws RuntimeException
     */
    public static function verify($token, $secretKey, Alg $alg = null)
    {
        if ($alg === null) {
            $alg = Algorithms::HS256();
        }

        $jwt = self::fromString($token);

        $parts = self::getParts($token);

        $hashData = sprintf('%s.%s', $parts->header, $parts->payload);

        if (!$alg->verify($hashData, $secretKey, self::b64UrlDecode($parts->signature))) {
            throw new RuntimeException('token validation failed');
        }

        return $jwt;
    }

    /**
     * @param string $token
     *
     * @return static
     */
    public static function fromString($token)
    {
        $parts = self::getParts($token);

        return new self(
            Header::createFromJson(self::b64UrlDecode($parts->header)),
            Payload::createFromJson(self::b64UrlDecode($parts->payload))
        );
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

    // some well known headers

    public function getKid()
    {
        return $this->getHeader('kid');
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

    // some well known claims

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
     * @return stdClass
     * @throws InvalidArgumentException
     */
    public static function getParts($token)
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new InvalidArgumentException('invalid token format');
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
