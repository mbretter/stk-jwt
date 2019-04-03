<?php

namespace Stk\JWT;

class Algorithms
{
    // HMAC

    public static function HS256()
    {
        return new Alg('HS256', function ($length) {
            return openssl_random_pseudo_bytes($length ?: 32);
        }, function ($data, $secret) {
            return hash_hmac('sha256', $data, $secret, true);
        });
    }

    public static function HS384()
    {
        return new Alg('HS384', function ($length) {
            return openssl_random_pseudo_bytes($length ?: 48);
        }, function ($data, $secret) {
            return hash_hmac('sha384', $data, $secret, true);
        });
    }

    public static function HS512()
    {
        return new Alg('HS512', function ($length) {
            return openssl_random_pseudo_bytes($length ?: 64);
        }, function ($data, $secret) {
            return hash_hmac('sha512', $data, $secret, true);
        });
    }

    // RSA

    public static function RS256()
    {
        return new Alg('RS256', function ($bits) {
            return Algorithms::makeRSAKey($bits);
        }, function ($data, $key) {
            openssl_sign($data, $jwt, $key, OPENSSL_ALGO_SHA256);

            return $jwt;
        }, function ($data, $key, $sig) {
            return openssl_verify($data, $sig, $key, OPENSSL_ALGO_SHA256) === 1;
        });
    }

    public static function RS384()
    {
        return new Alg('RS384', function ($bits) {
            return Algorithms::makeRSAKey($bits);
        }, function ($data, $key) {
            openssl_sign($data, $jwt, $key, OPENSSL_ALGO_SHA384);

            return $jwt;
        }, function ($data, $key, $sig) {
            return openssl_verify($data, $sig, $key, OPENSSL_ALGO_SHA384) === 1;
        });
    }

    public static function RS512()
    {
        return new Alg('RS512', function ($bits) {
            return Algorithms::makeRSAKey($bits);
        }, function ($data, $key) {
            openssl_sign($data, $jwt, $key, OPENSSL_ALGO_SHA512);

            return $jwt;
        }, function ($data, $key, $sig) {
            return openssl_verify($data, $sig, $key, OPENSSL_ALGO_SHA512) === 1;
        });
    }

    // EC

    public static function ES256()
    {
        return new Alg('ES256', function ($curveName) {
            if ($curveName === null) {
                $curveName = 'prime256v1';
            }

            return Algorithms::makeECKey($curveName);
        }, function ($data, $key) {
            openssl_sign($data, $jwt, $key, OPENSSL_ALGO_SHA256);

            return $jwt;
        }, function ($data, $key, $sig) {
            return openssl_verify($data, $sig, $key, OPENSSL_ALGO_SHA256) === 1;
        });
    }

    public static function ES384()
    {
        return new Alg('ES384', function ($curveName) {
            if ($curveName === null) {
                $curveName = 'secp384r1';
            }

            return Algorithms::makeECKey($curveName);
        }, function ($data, $key) {
            openssl_sign($data, $jwt, $key, OPENSSL_ALGO_SHA384);

            return $jwt;
        }, function ($data, $key, $sig) {
            return openssl_verify($data, $sig, $key, OPENSSL_ALGO_SHA384) === 1;
        });
    }

    public static function ES512()
    {
        return new Alg('ES512', function ($curveName) {
            if ($curveName === null) {
                $curveName = 'secp521r1';
            }

            return Algorithms::makeECKey($curveName);
        }, function ($data, $key) {
            openssl_sign($data, $jwt, $key, OPENSSL_ALGO_SHA512);

            return $jwt;
        }, function ($data, $key, $sig) {
            return openssl_verify($data, $sig, $key, OPENSSL_ALGO_SHA512) === 1;
        });
    }

    // Helper

    public static function makeRSAKey($bits = 2048)
    {
        $configargs = [
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => $bits ?: 2048
        ];

        $key = openssl_pkey_new($configargs);
        openssl_pkey_export($key, $pem);

        return $pem;
    }

    public static function makeECKey($curveName = 'prime256v1')
    {
        $configargs = [
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name'       => $curveName ?: 'prime256v1'
        ];
        //secp384r1,secp521r1
        $key = openssl_pkey_new($configargs);
        openssl_pkey_export($key, $pem);

        return $pem;
    }

    public static function derivePublicKey($privateKeyPem)
    {
        $key    = openssl_pkey_get_private($privateKeyPem);
        $pubkey = openssl_pkey_get_details($key);

        return $pubkey["key"];
    }
}