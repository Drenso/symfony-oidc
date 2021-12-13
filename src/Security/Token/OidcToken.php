<?php

namespace Drenso\OidcBundle\Security\Token;

use Drenso\OidcBundle\Model\OidcTokens;
use Drenso\OidcBundle\Model\OidcUserData;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Token\PostAuthenticationToken;

class OidcToken extends PostAuthenticationToken
{
  public const USER_DATA_ATTR = 'user_data';
  public const AUTH_DATA_ATTR = 'auth_data';

  public function __construct(Passport $passport, string $firewallName)
  {
    parent::__construct($passport->getUser(), $firewallName, $passport->getUser()->getRoles());

    // Load passport data into token
    $this->setAttribute(self::AUTH_DATA_ATTR, $passport->getAttribute(self::AUTH_DATA_ATTR));
    $this->setAttribute(self::USER_DATA_ATTR, $passport->getAttribute(self::USER_DATA_ATTR));
  }

  public function getAuthData(): OidcTokens
  {
    return $this->getAttribute(self::AUTH_DATA_ATTR);
  }

  public function getUserData(): OidcUserData
  {
    return $this->getAttribute(self::USER_DATA_ATTR);
  }
}
