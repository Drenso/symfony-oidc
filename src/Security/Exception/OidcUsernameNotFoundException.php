<?php

namespace Drenso\OidcBundle\Security\Exception;

use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;

/**
 * @phan-suppress PhanDeprecatedClass
 */
class OidcUsernameNotFoundException extends UsernameNotFoundException
{
  /**
   * OidcUsernameNotFoundException constructor.
   *
   * @param UsernameNotFoundException|NULL $previous
   */
  public function __construct(UsernameNotFoundException $previous = NULL)
  {
    parent::__construct('', 0, $previous);
  }
}
