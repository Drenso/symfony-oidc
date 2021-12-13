<?php

namespace Drenso\OidcBundle\Security\Exception;

use RuntimeException;

class UnsupportedManagerException extends RuntimeException
{
  public function __construct()
  {
    parent::__construct('This bundle no longer support the old Symfony authentication methods, make sure to enable `enable_authenticator_manager` in the Symfony security settings.');
  }
}
