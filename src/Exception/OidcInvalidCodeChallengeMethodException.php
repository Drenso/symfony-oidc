<?php

namespace Drenso\OidcBundle\Exception;

use LogicException;

class OidcInvalidCodeChallengeMethodException extends LogicException
{
  public function __construct(string $method)
  {
    parent::__construct(sprintf('The given method "%s" is not a valid code challenge method.', $method));
  }
}
