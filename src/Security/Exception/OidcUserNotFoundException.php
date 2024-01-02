<?php

namespace Drenso\OidcBundle\Security\Exception;

use Symfony\Component\Security\Core\Exception\UserNotFoundException;

class OidcUserNotFoundException extends UserNotFoundException
{
  public function __construct(string $message, ?UserNotFoundException $previous = null)
  {
    parent::__construct($message, 0, $previous);
  }
}
