<?php

namespace Drenso\OidcBundle\Model;

use Drenso\OidcBundle\Exception\OidcException;
use stdClass;

/** Contains the access and id tokens retrieved from the identity provider. */
class OidcTokens extends UnvalidatedOidcTokens
{
  /** @throws OidcException */
  public function __construct(UnvalidatedOidcTokens|stdClass $tokens)
  {
    // These are the only required parameters per https://tools.ietf.org/html/rfc6749#section-4.2.2
    if ($tokens instanceof UnvalidatedOidcTokens) {
      if ((null === $tokens->idToken) || (null === $tokens->accessToken)) {
        throw new OidcException('Invalid token object.');
      }
    } else {
      if (!isset($tokens->id_token) || !isset($tokens->access_token)) {
        throw new OidcException('Invalid token object.');
      }
    }

    parent::__construct($tokens);
  }

  public function getAccessToken(): string
  {
    return $this->accessToken ?? throw new OidcException('Access token not available');
  }

  public function getIdToken(): string
  {
    return $this->idToken ?? throw new OidcException('ID token not available');
  }
}
