<?php

namespace Drenso\OidcBundle\Model;

use Drenso\OidcBundle\Exception\OidcException;
use stdClass;

/**
 * Contains the access and id tokens retrieved from OpenID authentication.
 */
class OidcTokens extends UnvalidatedOidcTokens
{
  /** @throws OidcException */
  public function __construct(object $tokens)
  {
    // These are the only required parameters per https://tools.ietf.org/html/rfc6749#section-4.2.2
    if ($tokens instanceof stdClass) {
      if (!isset($tokens->id_token) || !isset($tokens->access_token)) {
        throw new OidcException('Invalid token object.');
      }
    } elseif ($tokens instanceof UnvalidatedOidcTokens) {
      if ((null === $tokens->getIdToken()) || (null === $tokens->getAccessToken())) {
        throw new OidcException('Invalid token object.');
      }
    }

    parent::__construct($tokens);
  }

  public function getAccessToken(): string
  {
    return $this->accessToken;
  }

  public function getIdToken(): string
  {
    return $this->idToken;
  }
}
