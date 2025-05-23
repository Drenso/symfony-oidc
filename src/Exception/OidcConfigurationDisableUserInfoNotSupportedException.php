<?php

namespace Drenso\OidcBundle\Exception;

class OidcConfigurationDisableUserInfoNotSupportedException extends OidcException
{
  public function __construct()
  {
    parent::__construct('User identifier from id_token should be enabled.');
  }
}
