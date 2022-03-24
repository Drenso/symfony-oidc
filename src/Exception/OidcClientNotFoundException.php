<?php

namespace Drenso\OidcBundle\Exception;

use Throwable;

class OidcClientNotFoundException extends OidcException
{
  public function __construct(string $name, Throwable $previous = null)
  {
    parent::__construct(sprintf('Client "%s" does not exist.', $name), previous: $previous);
  }
}
