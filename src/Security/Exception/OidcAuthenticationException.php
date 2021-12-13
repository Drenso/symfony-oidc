<?php

namespace Drenso\OidcBundle\Security\Exception;

use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Throwable;

class OidcAuthenticationException extends AuthenticationException
{
  public function __construct(
      string         $message,
      Throwable      $previous = NULL)
  {
    parent::__construct($message, 0, $previous);
  }
}
