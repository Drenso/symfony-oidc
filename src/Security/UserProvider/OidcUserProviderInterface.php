<?php

namespace Drenso\OidcBundle\Security\UserProvider;

use Drenso\OidcBundle\Exception\OidcException;
use Drenso\OidcBundle\Model\OidcTokens;
use Drenso\OidcBundle\Model\OidcUserData;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

interface OidcUserProviderInterface extends UserProviderInterface
{
  /** @throws OidcException Can be thrown when the user cannot be created */
  public function ensureUserExists(string $userIdentifier, OidcUserData $userData, OidcTokens $tokens);

  /** Custom user loader method to be able to distinguish oidc authentications */
  public function loadOidcUser(string $userIdentifier): UserInterface;
}
