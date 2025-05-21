<?php

namespace Drenso\OidcBundle\Security\Exception;

use Drenso\OidcBundle\Exception\OidcException;

class OidcConfigurationDisableUserInfoNotSupportedException extends OidcException
{
  public function __construct()
  {
    parent::__construct('User identifier from id_token should be enabled.');
  }
}
