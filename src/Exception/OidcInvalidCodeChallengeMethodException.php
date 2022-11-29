<?php

namespace Drenso\OidcBundle\Exception;

class OidcInvalidCodeChallengeMethodException extends OidcException
{
  public function __construct(string $method)
  {
    parent::__construct(sprintf('The given method "%s" is not a valid code challenge method.', $method));
  }
}
