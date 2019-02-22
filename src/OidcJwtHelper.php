<?php

namespace Drenso\OidcBundle;

use Drenso\OidcBundle\Security\Exception\OidcAuthenticationException;
use phpseclib\Crypt\RSA;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

/**
 * Class OidcJwtHelper
 * Contains helper functions to decode/verify JWT data
 *
 * @author BobV
 */
class OidcJwtHelper
{

  /**
   * @var SessionInterface
   */
  protected $session;

  /**
   * @var OidcUrlFetcher
   */
  protected $urlFetcher;

  /**
   * @var string
   */
  private $clientId;

  /**
   * OidcJwtHelper constructor.
   *
   * @param SessionInterface $session
   * @param OidcUrlFetcher   $urlFetcher
   * @param string           $clientId
   */
  public function __construct(SessionInterface $session, OidcUrlFetcher $urlFetcher, string $clientId)
  {
    $this->session    = $session;
    $this->urlFetcher = $urlFetcher;
    $this->clientId   = $clientId;
  }

  /**
   * Per RFC4648, "base64 encoding with URL-safe and filename-safe
   * alphabet".  This just replaces characters 62 and 63.  None of the
   * reference implementations seem to restore the padding if necessary,
   * but we'll do it anyway.
   *
   * @param $base64url
   *
   * @return string
   */
  private static function b64url2b64($base64url)
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
   *
   * @param $base64url
   *
   * @return bool|string
   */
  private static function base64url_decode($base64url)
  {
    return base64_decode(self::b64url2b64($base64url));
  }

  /**
   * @param string $str
   *
   * @return string
   */
  private static function urlEncode($str)
  {
    $enc = base64_encode($str);
    $enc = rtrim($enc, "=");
    $enc = strtr($enc, "+/", "-_");

    return $enc;
  }

  /**
   * @param string $jwt     string encoded JWT
   * @param int    $section the section we would like to decode
   *
   * @return object
   */
  public function decodeJwt(string $jwt, $section = 0)
  {
    $parts = explode(".", $jwt);

    return json_decode(self::base64url_decode($parts[$section]));
  }

  /**
   * @param                 $issuer
   * @param                 $claims
   * @param OidcTokens|null $tokens
   *
   * @return bool
   */
  public function verifyJwtClaims($issuer, $claims, OidcTokens $tokens = NULL)
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
    $nonce = $this->session->get(OidcClient::OIDC_SESSION_NONCE);
    $this->session->remove(OidcClient::OIDC_SESSION_NONCE);

    /** @noinspection PhpUndefinedVariableInspection */
    return (($claims->iss == $issuer)
        && (($claims->aud == $this->clientId) || (in_array($this->clientId, $claims->aud)))
        && ($claims->nonce == $nonce)
        && (!isset($claims->exp) || $claims->exp >= time())
        && (!isset($claims->nbf) || $claims->nbf <= time())
        && (!isset($claims->at_hash) || $claims->at_hash == $expectedAtHash)
    );
  }

  /**
   * @param            $jwksUri
   * @param OidcTokens $tokens encoded JWT
   *
   * @return bool
   */
  public function verifyJwtSignature($jwksUri, OidcTokens $tokens)
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

  /**
   * @param string $hashtype
   * @param object $key
   * @param        $payload
   * @param        $signature
   *
   * @return bool
   */
  public function verifyRsaJwtSignature($hashtype, $key, $payload, $signature)
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

    $rsa = new RSA();
    $rsa->setHash($hashtype);
    $rsa->loadKey($public_key_xml, RSA::PUBLIC_FORMAT_XML); // @phan-suppress-current-line PhanTypeMismatchArgument
    $rsa->signatureMode = RSA::SIGNATURE_PKCS1;

    return $rsa->verify($payload, $signature);
  }

  /**
   * @param OidcTokens $tokens
   *
   * @return object
   */
  private function getAccessTokenHeader(OidcTokens $tokens)
  {
    return $this->decodeJwt($tokens->getAccessToken(), 0);
  }

  /**
   * @param $keys
   * @param $header
   *
   * @return mixed
   */
  private function getKeyForHeader($keys, $header)
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
