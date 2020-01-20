<?php

namespace StkTest\Jwt;

use InvalidArgumentException;
use RuntimeException;
use Stk\JWT\Algorithms;
use Stk\JWT\JWT;

class VerifyTest extends Base
{
    protected $probes = [];

    protected $rsakey;

    public function setUp(): void
    {
        $this->rsakey = <<<EOT1
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDiN3cyXMQ6oK51
N26TghTHhaArXXa2/4DLRH2gqk81pvnyF8IYniFgRelMtvEaBegQX3EV+efDv1pZ
avHWEq3cTE77GwosEqH4S50YfH/9lTmTNBqEuIRC9VreS64iLnJFg40KpAIuL1Ba
NQ8mpBooGmKQGi1LEikEBulvGDjVc5i9t2winP7d8f6wniWX1ZGMeudUDWl9s1Jx
j0M4I/3HtbP93ilEI7tniUB3ZEshazJ19k5L6qsjBf1Noacg8YSse8Z/QN+qfm9y
/PSXJgwWkWtDYgQM1CZqG5WnQ1UK4rHJInQcCzTVk2Fv0jUOk8aAzUSoVMAHYrdh
6qo3lb5VAgMBAAECggEAFhBC1+6kVPOHEHevmUN+s1cdIB2ljoOtFCZB+oGh6CG5
DxuyGqSRrMokzw6oxVj+IVqttO8C49yt+zqrC64Wtv3aVjN08od+tLDrSZAbC6ia
TPkv/PHiNIWprzTCbyMIki8aeoc0jzyeIa47JBGtW2v3YQaslD3ZMkNaUTOTl33X
2apSvcR0DsaJ7d6PpDvvbiFxroK/hRws+FIM7OfF2Lt5/jlf8dYOzAl9gaDAJK3b
DdOmUtwpG9aoY6xnQsE5e3bNGYPtO2b0OnxX97uJx9Suu/STHhjeT37OqH5z/CRm
p4Y8vuw2+5QOhmgow5yO9HKxHJvm1jQeDJzfRXVDoQKBgQD3m7pvUASzbbXB7ZqJ
A+7zNAVHiWhr3g3TMn0MqRRktPpIdpHj54pY+xgikZ+qduoP3LWwtMg0kmbqIWav
ER6Utrd3xLgvhkWwMUircUG2D+1PcsM5h+RGPtDGf8QS5DYoq56khz22x/d1jt82
4RghAXE+s5T/Y/GnE5ait917pwKBgQDp4iQ4adsvbyuMXW1xiDkilpUH7G318I9O
XYxlYQ40xIBbcLwp/8NU4gRwb5wvquesizTqOcxv1ihbfWuNZvQW3HGfIvGCWeGc
6ohK6DwQrzu3LwGC9oUBeefhH+xV6XZGopsHcdcwNEF79dPyfgLAsPShst27bX79
sYkPamRFowKBgQCs6R0qepCt1GFnCcwu/oYxZBSDvlsjaK/y2oElBDXvlcpqLBL5
OkoMlVxnV5ZObjhJ13Ex8y0UOWCRA743ZxcZ9vbsNn4BAh1MSz5aKv8easToBFZ8
qH8q5tbYp4R/RMrlX+OrNZ5NNBuFBr6uDkbRVbaFeNcF+f9ZE37QJuIOZQKBgQDJ
GspKN7tgbhbj+vHATYHTW+eJiKKEdvTCTW4LPgkZFl3IQoeJFYK/2hg3FcEWu725
f3lgbZJ8F4lcIdv5Gi2H+sU4MLO5gc+dPY0z27zKG+MdAC4sjgyP2GKqEOkGdlhd
JDRpklmV+VjVXeuA9xkm1wGCiGpgXyZyvdU8jB7sQQKBgQCbKNLrT2s6RzkP0L2P
3kSeOombvBXfk/aJx2OZ9YATeY2aeXgsiorJ2Pi+yi9xdMVgmJ7AoVSh3CmchuX0
XTG7ysgCAtm6aGkLcuAW/iTWz04Sl2XYgEPiJvQ4RbPZXA7Ai40N1ojlFm5v568b
MPs9wYO9NiJWFAXWR9EeA6FGgQ==
-----END PRIVATE KEY-----
EOT1;

        $this->probes[] = [
            'alg'    => Algorithms::HS256(),
            'secret' => '2Ro2rR9nCoCqYlEbhksPJDKaa4K3Lxdd/OgLI0LbD1I=',
            'jwt'    => 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.1pkIXLcblcHuN12SioD-TeDSRXv3cWcM_JnOKw03XTg'
        ];
        $this->probes[] = [
            'alg'    => Algorithms::HS384(),
            'secret' => 'hZq/XflRZLTGPHZBLLt+hAX7XpOjGctyOv8pfR9nmTVDzQjjAmSdQTuoQbkDOUxn',
            'jwt'    => 'eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.Jx9JZse10iEvAYVLXPb5619d1q_afjrZcMk0LU2Ms9h3Gcl5DWwSHQ6vgUaNq8ar'
        ];
        $this->probes[] = [
            'alg'    => Algorithms::HS512(),
            'secret' => 'UfmDHV18BbCSZdr5/asbtdLyy3jQBquqb686ed389O8FgC5Otil5iPjlwp2m3Ye144rnsB21cnTMZmEwIPffmA==',
            'jwt'    => 'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.I3BuQx7KX2RMJ5eRlTY_kEKbFn6tUalZDj1--BgZUI0pY0CIAkPXMsrrzwJB5HtJpq8VmPjPsCzjVvs43ZUYhw'
        ];
        $this->probes[] = [
            'alg' => Algorithms::RS256(),
            'key' => $this->rsakey,
            'jwt' => 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.bwCbKMQlUJbY0Wm5eDGl7SK0EsxhfSaT3rKn9hazCpTkuu1Zy9vE96KFinj51_jPI9_DpNNrsawoGovXhIOGSWAU97Q4eqP5MQ_EVMQczoHg3pjPFQBcyip6l20XlPycNDu2sE8zHq2hgjJcqpgNUla7BDwyRVg0Ut9YzClVQGkXC_SiugI0uLwiUDk677OdKeU6dCecBufumTDBH50kT3CSgL0q0WA472QFVxVkCj_tGSbpCKu3N0bmBJqVi1n65hEyO8GUbBcGu4f46CkLuMhx6DKoYu3nMUZBiXC-yYp0UicNfHSMjLV5-rzD0gq-Q1e6Cc83RZK3nooMEv4Flg'
        ];
        $this->probes[] = [
            'alg' => Algorithms::RS384(),
            'key' => $this->rsakey,
            'jwt' => 'eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.PrKldml2uslVCxTQjFL3SqcFVZCVkRd13jzVFFpBGpax4CnolfA_9O3JRvA44bHRxxKOO2xBBXqrwoEuyF5vYXu1kJB2bmCvAPKZ229qwy7G7tFPC9jnYKseo-AXyoezVZdwfXxAERLSVS7I0NxyLR3-S_Olxvc9afBs-490BVEWleTg8vBjxGU608waKO6lNZyZjRvwKkFguPpkbaQpibmfCH5vtD_IY8x512YIyuPB99OgtBewVX-j6yil3joYmL3jaki-FafJ4Mjl4PjPv0bSQoLvgZLhGd8YYtKfASOKegQ1s-IdS02sS8jQG4tCXmA3w7j7CtDYFqodE9RiNg'
        ];
        $this->probes[] = [
            'alg' => Algorithms::RS512(),
            'key' => $this->rsakey,
            'jwt' => 'eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.B6SYGReSngTXbYeyaYuf1LhsYVqYyeCXeU7qrqhZIUN_Q8VfFm1CdFhlAK20nBRbqr0_GqJWt6DYepRdlyr_-8tEbm8TUx5K7VeUqfg48nj6x2APoCirkhEWxLvEbCHlsqg3zMclyyKuMvzRoVBbSbk2dnBuzmYDT1MH5QRhTS12tHX-8u0v-Yli3zwGddgqq03H926oDTk0So_LuhjX1yEW7YHx85NyckNksMY8-DH6JGE7Mrv9PNAGVL3MaBcOC33Oyu997LL1L7wATYCwqvOxCx0gtzR_Gu6EYinl6gUgGbcoMy7m1tn-H48FofBlvMGJdFVWlPmtcysn0hBZ9Q'
        ];
    }

    public function testVerifyWithDefaults()
    {
        $token  = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.1pkIXLcblcHuN12SioD-TeDSRXv3cWcM_JnOKw03XTg';
        $secret = base64_decode('2Ro2rR9nCoCqYlEbhksPJDKaa4K3Lxdd/OgLI0LbD1I=');

        $jwt = JWT::verify($token, $secret);

        $this->assertInstanceOf(JWT::class, $jwt);
    }

    public function testVerifyInvalidTokenFormat()
    {
        $token  = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.1pkIXLcblcHuN12SioD-TeDSRXv3cWcM_JnOKw03XTg';
        $secret = base64_decode('2Ro2rR9nCoCqYlEbhksPJDKaa4K3Lxdd/OgLI0LbD1I=');

        $this->expectException(InvalidArgumentException::class);
        $jwt = JWT::verify($token, $secret);

        $this->assertInstanceOf(JWT::class, $jwt);
    }

    public function testVerifyInvalidTokenFormatEmptyJson()
    {
        $token  = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..1pkIXLcblcHuN12SioD-TeDSRXv3cWcM_JnOKw03XTg';
        $secret = base64_decode('2Ro2rR9nCoCqYlEbhksPJDKaa4K3Lxdd/OgLI0LbD1I=');

        $this->expectException(InvalidArgumentException::class);

        $jwt = JWT::verify($token, $secret);

        $this->assertInstanceOf(JWT::class, $jwt);
    }

    public function testVerifyInvalidJson()
    {
        $token  = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.1pkIXLcblcHuN12SioD-TeDSRXv3cWcM_JnOKw03XTg';
        $secret = base64_decode('2Ro2rR9nCoCqYlEbhksPJDKaa4K3Lxdd/OgLI0LbD1I=');
        $this->expectException(InvalidArgumentException::class);

        $jwt = JWT::verify($token, $secret);

        $this->assertInstanceOf(JWT::class, $jwt);
    }

    public function testVerifyInvalidSignature()
    {
        $token  = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.kIXLcblcHuN12SioD-TeDSRXv3cWcM_JnOKw03XTg';
        $secret = base64_decode('2Ro2rR9nCoCqYlEbhksPJDKaa4K3Lxdd/OgLI0LbD1I=');
        $this->expectException(RuntimeException::class);

        $jwt = JWT::verify($token, $secret);

        $this->assertFalse($jwt);
    }

    public function testVerifyHMACRSA()
    {
        foreach ($this->probes as $p) {
            if (isset($p['key'])) {
                $key    = openssl_pkey_get_private($p['key']);
                $pubkey = openssl_pkey_get_details($key);
                $secret = $pubkey["key"];
            } else {
                $secret = base64_decode($p['secret']);
            }

            $jwt = JWT::verify($p['jwt'], $secret, $p['alg']);
            $this->assertInstanceOf(JWT::class, $jwt);
        }
    }

    public function testValidate()
    {
        $token  = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.1pkIXLcblcHuN12SioD-TeDSRXv3cWcM_JnOKw03XTg';
        $secret = base64_decode('2Ro2rR9nCoCqYlEbhksPJDKaa4K3Lxdd/OgLI0LbD1I=');

        $res = JWT::validate($token, $secret);
        $this->assertInstanceOf(JWT::class, $res);
    }

    public function testValidateFailed()
    {
        $token  = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpaVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.1pkIXLcblcHuN12SioD-TeDSRXv3cWcM_JnOKw03XTg';
        $secret = base64_decode('2Ro2rR9nCoCqYlEbhksPJDKaa4K3Lxdd/OgLI0LbD1I=');

        $res = JWT::validate($token, $secret);
        $this->assertFalse($res);
    }

    public function testValidateWithInvalidTokenFormat()
    {
        $token  = 'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.1pkIXLcblcHuN12SioD-TeDSRXv3cWcM_JnOKw03XTg';
        $secret = base64_decode('2Ro2rR9nCoCqYlEbhksPJDKaa4K3Lxdd/OgLI0LbD1I=');

        $res = JWT::validate($token, $secret);
        $this->assertFalse($res);
    }
}