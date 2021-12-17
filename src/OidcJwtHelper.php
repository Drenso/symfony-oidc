<?php


namespace Drenso\OidcBundle;

use Drenso\OidcBundle\Exception\OidcException;
use Drenso\OidcBundle\Model\OidcTokens;
use Drenso\OidcBundle\Security\Exception\OidcAuthenticationException;
use RuntimeException;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Contains helper functions to decode/verify JWT data
 */
class OidcJwtHelper
{
  public function __construct(
      protected RequestStack   $requestStack,
      protected OidcUrlFetcher $urlFetcher,
      private string           $clientId)
  {
  }

  /**
   * Per RFC4648, "base64 encoding with URL-safe and filename-safe
   * alphabet".  This just replaces characters 62 and 63.  None of the
   * reference implementations seem to restore the padding if necessary,
   * but we'll do it anyway.
   */
  private static function b64url2b64(string $base64url): string
  {
    // "Shouldn't" be necessary, but why not
    $padding = strlen($base64url) % 4;
    if ($padding > 0) {
      $base64url .= str_repeat("=", 4 - $padding);
    }

    return strtr($base64url, '-_', '+/');
  }

  /**
   * A wrapper around base64_decode which decodes Base64URL-encoded data,
   * which is not the same alphabet as base64.
   */
  private static function base64url_decode(string $base64url): string|false
  {
    return base64_decode(self::b64url2b64($base64url));
  }

  private static function urlEncode(string $str): string
  {
    $enc = base64_encode($str);
    $enc = rtrim($enc, "=");

    return strtr($enc, "+/", "-_");
  }

  /**
   * @param string $jwt     string encoded JWT
   * @param int    $section the section we would like to decode
   *
   * @return object|null Returns null when a non-valid JWT is encountered
   * @throws OidcException
   */
  public function decodeJwt(string $jwt, int $section = 0): ?object
  {
    if ($section < 0 || $section > 2) {
      throw new OidcException('Invalid JWT section requested');
    }

    $parts = explode(".", $jwt);

    if (count($parts) !== 3) {
      // When there are not exactly three parts, the passed string is not a JWT
      return NULL;
    }

    return json_decode(self::base64url_decode($parts[$section]));
  }

  public function verifyJwtClaims(string $issuer, ?object $claims, ?OidcTokens $tokens = NULL): bool
  {
    if (isset($claims->at_hash) && $tokens->getAccessToken() !== NULL) {
      $accessTokenHeader = $this->getAccessTokenHeader($tokens);
      if (isset($accessTokenHeader->alg) && $accessTokenHeader->alg != 'none') {
        $bit = substr($accessTokenHeader->alg, 2, 3);
      } else {
        // TODO: Error case. throw exception???
        $bit = '256';
      }
      $len            = ((int)$bit) / 16;
      $expectedAtHash = self::urlEncode(
          substr(hash('sha' . $bit, $tokens->getAccessToken(), true), 0, $len));
    }

    // Get and remove nonce from session
    $nonce = $this->requestStack->getSession()->get(OidcClient::OIDC_SESSION_NONCE);
    $this->requestStack->getSession()->remove(OidcClient::OIDC_SESSION_NONCE);

    /** @noinspection PhpUndefinedVariableInspection */
    return (($claims->iss == $issuer)
        && (($claims->aud == $this->clientId) || (in_array($this->clientId, $claims->aud)))
        && ($claims->nonce == $nonce)
        && (!isset($claims->exp) || $claims->exp >= time())
        && (!isset($claims->nbf) || $claims->nbf <= time())
        && (!isset($claims->at_hash) || $claims->at_hash == $expectedAtHash)
    );
  }

  public function verifyJwtSignature(string $jwksUri, OidcTokens $tokens): bool
  {
    // Check JWT information
    if (!$jwksUri) {
      throw new OidcAuthenticationException("Unable to verify signature due to no jwks_uri being defined");
    }

    $parts     = explode(".", $tokens->getIdToken());
    $signature = self::base64url_decode(array_pop($parts));
    $header    = json_decode(self::base64url_decode($parts[0]));
    $payload   = implode(".", $parts);
    $jwks      = json_decode($this->urlFetcher->fetchUrl($jwksUri));
    if ($jwks === NULL) {
      throw new OidcAuthenticationException('Error decoding JSON from jwks_uri');
    }

    // Check for supported signature types
    if (!in_array($header->alg, ['RS256', 'RS384', 'RS512'])) {
      throw new OidcAuthenticationException('No support for signature type: ' . $header->alg);
    }

    $hashType = 'sha' . substr($header->alg, 2);

    return $this->verifyRsaJwtSignature($hashType, $this->getKeyForHeader($jwks->keys, $header), $payload, $signature);
  }

  public function verifyRsaJwtSignature(string $hashtype, object $key, $payload, $signature): bool
  {
    if (!(property_exists($key, 'n') and property_exists($key, 'e'))) {
      throw new OidcAuthenticationException('Malformed key object');
    }

    /**
     * We already have base64url-encoded data, so re-encode it as
     * regular base64 and use the XML key format for simplicity.
     */
    $public_key_xml = "<RSAKeyValue>\r\n" .
        "  <Modulus>" . self::b64url2b64($key->n) . "</Modulus>\r\n" .
        "  <Exponent>" . self::b64url2b64($key->e) . "</Exponent>\r\n" .
        "</RSAKeyValue>";

    if (class_exists('\phpseclib3\Crypt\RSA')) {
      /** @phan-suppress-next-line PhanUndeclaredMethod */
      $rsa = \phpseclib3\Crypt\RSA::load($public_key_xml)
          ->withPadding(\phpseclib3\Crypt\RSA::ENCRYPTION_PKCS1 | \phpseclib3\Crypt\RSA::SIGNATURE_PKCS1)
          ->withHash($hashtype);
    } else if (class_exists('\phpseclib\Crypt\RSA')) {
      /** @phan-suppress-next-line PhanUndeclaredClassMethod */
      $rsa = new \phpseclib\Crypt\RSA();
      /** @phan-suppress-next-line PhanUndeclaredClassMethod */
      $rsa->setHash($hashtype);
      /** @phan-suppress-next-line PhanTypeMismatchArgument,PhanUndeclaredClassConstant,PhanUndeclaredClassMethod */
      $rsa->loadKey($public_key_xml, \phpseclib\Crypt\RSA::PUBLIC_FORMAT_XML);
      /** @phan-suppress-next-line PhanUndeclaredClassConstant,PhanUndeclaredClassProperty */
      $rsa->signatureMode = \phpseclib\Crypt\RSA::SIGNATURE_PKCS1;
    } else {
      throw new RuntimeException('Unable to find phpseclib Crypt/RSA.php.  Ensure phpseclib/phpseclib is installed.');
    }

    /** @phan-suppress-next-line PhanUndeclaredClassMethod */
    return $rsa->verify($payload, $signature);
  }

  private function getAccessTokenHeader(OidcTokens $tokens): ?object
  {
    return $this->decodeJwt($tokens->getAccessToken(), 0);
  }

  private function getKeyForHeader($keys, $header): object
  {
    foreach ($keys as $key) {
      if ($key->kty == 'RSA') {
        if (!isset($header->kid) || $key->kid == $header->kid) {
          return $key;
        }
      } else {
        if ($key->alg == $header->alg && $key->kid == $header->kid) {
          return $key;
        }
      }
    }
    if (isset($header->kid)) {
      throw new OidcAuthenticationException(sprintf('Unable to find a key for (algorithm, kid): %s, %s', $header->alg, $header->kid));
    } else {
      throw new OidcAuthenticationException('Unable to find a key for RSA');
    }
  }
}
