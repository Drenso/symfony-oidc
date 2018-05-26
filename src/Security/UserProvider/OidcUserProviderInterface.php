<?php

namespace Drenso\OidcBundle\Security\UserProvider;

use Drenso\OidcBundle\Security\Authentication\Token\OidcToken;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

interface OidcUserProviderInterface extends UserProviderInterface
{

  /**
   * Call this method to create a new user from the data available in the token,
   * but only if the user does not exists yet.
   * If it does exist, return that user.
   *
   * @param OidcToken $token
   *
   * @return UserInterface
   */
  public function loadUserByToken(OidcToken $token);

}
