<?php

namespace Drenso\OidcBundle;

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
   * @var \DateTime
   */
  private $expiry;

  /**
   * @var string
   */
  private $idToken;

  /**
   * @var string
   */
  private $refreshToken;

  /**
   * @var string[]
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
    if (!isset($tokens->id_token) || !isset($tokens->access_token) || !isset($tokens->expires_in)) {
      throw new OidcException('Invalid token object.');
    }

    $expiry = \DateTime::createFromFormat('U', (string) time() + $tokens->expires_in);
    assert($expiry instanceof \DateTime);

    $this->accessToken  = $tokens->access_token;
    $this->idToken      = $tokens->id_token;
    $this->expiry       = $expiry;
    $this->refreshToken = $tokens->refresh_token;
    $this->scope        = explode(' ', $tokens->scope);
  }

  /**
   * @return string
   */
  public function getAccessToken(): string
  {
    return $this->accessToken;
  }

  public function getExpiry(): \DateTime
  {
    return $this->expiry;
  }

  public function getIdToken(): string
  {
    return $this->idToken;
  }

  public function getRefreshToken(): string
  {
    return $this->refreshToken;
  }

  public function getScope(): array
  {
    return $this->scope;
  }
}
