<?php

namespace Drenso\OidcBundle\Model;

use stdClass;

class OidcExchangeTokens extends OidcTokens
{
  public function __construct(stdClass $tokens)
  {
    $tokens->id_token = '';
    parent::__construct($tokens);
  }
}
