<?php

namespace StkTest\Jwt;

use Stk\JWT\Algorithms;
use Stk\JWT\JWT;
use Stk\JWT\Header;
use Stk\JWT\Payload;

class SignTest extends Base
{
    protected $probes = [];

    protected $rsakey;

    public function setUp()
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

    public function testSignWithDefaults()
    {
        $secret = base64_decode('2Ro2rR9nCoCqYlEbhksPJDKaa4K3Lxdd/OgLI0LbD1I=');

        $payload = (new Payload())->with('sub', '1234567890')->with('name', "John Doe")->with('iat', 1516239022);

        $jwt   = new JWT(null, $payload);
        $token = $jwt->sign($secret);

        $this->assertEquals('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.1pkIXLcblcHuN12SioD-TeDSRXv3cWcM_JnOKw03XTg', $token);
    }

    public function testSignHMACRSA()
    {
        foreach ($this->probes as $p) {
            $header  = new Header([], $p['alg']->getName());
            $payload = new Payload([
                'sub'  => '1234567890',
                'name' => "John Doe",
                'iat'  => 1516239022
            ]);

            $jwt   = new JWT($header, $payload);
            $token = $jwt->sign(isset($p['secret']) ? base64_decode($p['secret']) : $p['key'], $p['alg']);

            $this->assertEquals($p['jwt'], $token);
        }
    }

    public function testSignES256()
    {
        $ecKey = <<<EOT2
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBLiFqVdyjO/i0pRgxr25Km240dxOTwiTxxwZbwA2EJnoAoGCCqGSM49
AwEHoUQDQgAE9VEcb6S0G0mrNLXaQr5ApxX3ubtK5fN04UpM8UV/H70ykEsetlpd
mDeb7B8R0dxHIyaFP8QOU4VzqgiPZUP+aw==
-----END EC PRIVATE KEY-----
EOT2;

        $header  = new Header([], Algorithms::ES256()->getName());
        $payload = new Payload([
            'sub'  => '1234567890',
            'name' => "John Doe",
            'iat'  => 1516239022
        ]);

        $encoder = new JWT($header, $payload);
        $jwt     = $encoder->sign($ecKey, Algorithms::ES256());
        $this->assertIsString($jwt); // EC hashes have random val, its not possible to get repeatable results

        // derive public key and verify the signature
        $key    = openssl_pkey_get_private($ecKey);
        $pubkey = openssl_pkey_get_details($key);
        $pubkey = $pubkey["key"];

        $this->assertTrue($encoder->verify($jwt, $pubkey, Algorithms::ES256()));
    }

    public function testSignES384()
    {
        $ecKey = <<<EOT2
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDAIFb8gg0tAHSR421KebSue86JMAx2tUeONG/LVInXsQqKLHsxyfkqT
AsetiRsv+SKgBwYFK4EEACKhZANiAAQ8n6JCEW0Fag70nVMDN4PYlznG4SxZqgc6
S8ZbWxmiO4TRlIGS6JJ9abk7r61Ex40V+fNCAIAGkGscc46t0lNfkJriVX8EN7iT
OSDG49LE8xhlWX0mun34kcqnEfeO8Mc=
-----END EC PRIVATE KEY-----
EOT2;

        $header  = new Header([], Algorithms::ES384()->getName());
        $payload = new Payload([
            'sub'  => '1234567890',
            'name' => "John Doe",
            'iat'  => 1516239022
        ]);

        $jwt = new JWT($header, $payload);
        $token     = $jwt->sign($ecKey, Algorithms::ES384());
        $this->assertIsString($token); // EC hashes have random val, its not possible to get repeatable results

        // derive public key and verify the signature
        $key    = openssl_pkey_get_private($ecKey);
        $pubkey = openssl_pkey_get_details($key);
        $pubkey = $pubkey["key"];

        $this->assertTrue($jwt->verify($token, $pubkey, Algorithms::ES384()));
    }

    public function testSignES512()
    {
        $ecKey = <<<EOT2
-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIAIbfGBzvldbVVSKoyQyKwIub+W6nO3gCJ9f/74U34rzMDonQSFBID
V8qjIRIEU2Nl1COw4nBZrgirVeEVOw1G9hagBwYFK4EEACOhgYkDgYYABABLnmtg
Byhqd54GyTMW+l1FKcKY5n0qB4PibtVaWD7/SUF6hkW3x8tbw+2EDP0AJNAp8LXq
KOICQ0I6oJ6ET2RjowDjR22RiqeDp0qiEvEe2o2gjcijLjfJfySMaf68bBtFwO+X
Tk8ghO68nAfBOV3jCugSetFGnN553ecS504/d0TvKw==
-----END EC PRIVATE KEY-----
EOT2;

        $header  = new Header([], Algorithms::ES512()->getName());
        $payload = new Payload([
            'sub'  => '1234567890',
            'name' => "John Doe",
            'iat'  => 1516239022
        ]);

        $jwt   = new JWT($header, $payload);
        $token = $jwt->sign($ecKey, Algorithms::ES512());
        $this->assertIsString($token); // EC hashes have random val, its not possible to get repeatable results

        // derive public key and verify the signature
        $key    = openssl_pkey_get_private($ecKey);
        $pubkey = openssl_pkey_get_details($key);
        $pubkey = $pubkey["key"];

        $this->assertTrue($jwt->verify($token, $pubkey, Algorithms::ES512()));
    }
}