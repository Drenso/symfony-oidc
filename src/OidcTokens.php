<?php

namespace Drenso\OidcBundle;

use Drenso\OidcBundle\Exception\OidcException;

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
   * @var string
   */
  private $idToken;

  /**
   * OidcTokens constructor.
   *
   * @param \stdClass $tokens
   *
   * @throws OidcException
   */
  public function __construct(\stdClass $tokens)
  {
    if (!isset($tokens->id_token) || !isset($tokens->access_token)) {
      throw new OidcException("Invalid token object.");
    }
    $this->accessToken = $tokens->access_token;
    $this->idToken     = $tokens->id_token;
  }

  /**
   * @return string
   */
  public function getAccessToken(): string
  {
    return $this->accessToken;
  }

  /**
   * @return string
   */
  public function getIdToken(): string
  {
    return $this->idToken;
  }
}
