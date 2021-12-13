<?php

namespace Drenso\OidcBundle\Security\Exception;

use Symfony\Component\Security\Core\Exception\UserNotFoundException;

class OidcUserNotFoundException extends UserNotFoundException
{
  public function __construct(string $message, UserNotFoundException $previous = NULL)
  {
    parent::__construct($message, 0, $previous);
  }
}
