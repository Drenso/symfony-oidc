<?php

namespace Drenso\OidcBundle\Security\Exception;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

class OidcAuthenticationException extends AuthenticationException
{
  const TOKEN_UNSUPPORTED = 'Token unsupported';

  /**
   * OidcAuthenticationException constructor.
   *
   * @param string              $message
   * @param TokenInterface|NULL $token
   * @param \Throwable|NULL     $previous
   */
  public function __construct(string $message = "", TokenInterface $token = NULL, \Throwable $previous = NULL)
  {
    parent::__construct($message, 0, $previous);

    if ($token instanceof TokenInterface) {
      $this->setToken($token);
    }
  }
}
