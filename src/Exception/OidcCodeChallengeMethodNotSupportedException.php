<?php

namespace Drenso\OidcBundle\Exception;

class OidcCodeChallengeMethodNotSupportedException extends OidcException
{
  public function __construct(string $method)
  {
    parent::__construct(sprintf('The code challenge method "%s" is not supported by the IdP.', $method));
  }
}
