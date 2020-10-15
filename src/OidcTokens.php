<?php

namespace Drenso\OidcBundle;

use DateTimeImmutable;
use Drenso\OidcBundle\Exception\OidcException;
use stdClass;

/**
 * Class OidcTokens
 * Contains the access and id tokens retrieved from OpenID authentication
 *
 * @author BobV
 */
class OidcTokens
{

  /**
   * @var string
   */
  private $accessToken;

  /**
   * @var DateTimeImmutable|null
   */
  private $expiry;

  /**
   * @var string
   */
  private $idToken;

  /**
   * @var string|null
   */
  private $refreshToken;

  /**
   * @var string[]|null
   */
  private $scope;

  /**
   * OidcTokens constructor.
   *
   * @param stdClass $tokens
   *
   * @throws OidcException
   */
  public function __construct(stdClass $tokens)
  {
    // These are the only required parameters per https://tools.ietf.org/html/rfc6749#section-4.2.2
    if (!isset($tokens->id_token) || !isset($tokens->access_token)) {
      throw new OidcException('Invalid token object.');
    }

    $this->accessToken = $tokens->access_token;
    $this->idToken     = $tokens->id_token;

    if (isset($tokens->expires_in)) {
      $this->expiry = DateTimeImmutable::createFromFormat('U', (string)(time() + $tokens->expires_in));
    }

    if (isset($tokens->refresh_tokens)) {
      $this->refreshToken = $tokens->refresh_tokens;
    }

    if (isset($tokens->scope)) {
      $this->scope = explode(' ', $tokens->scope);
    }
  }

  public function getAccessToken(): string
  {
    return $this->accessToken;
  }

  public function getExpiry(): ?DateTimeImmutable
  {
    return $this->expiry;
  }

  public function getIdToken(): string
  {
    return $this->idToken;
  }

  public function getRefreshToken(): ?string
  {
    return $this->refreshToken;
  }

  /**
   * @return string[]|null
   */
  public function getScope(): ?array
  {
    return $this->scope;
  }
}
