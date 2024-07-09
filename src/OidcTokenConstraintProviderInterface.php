<?php

namespace Drenso\OidcBundle;

use Drenso\OidcBundle\Enum\OidcTokenType;
use Lcobucci\JWT\Validation\Constraint;

interface OidcTokenConstraintProviderInterface
{
  /**
   * Provide additional Token constraints to be checked during Token validation
   * @param OidcTokenType $tokenType
   * @return Constraint[]
   */
  public function getAdditionalConstraints(OidcTokenType $tokenType): array;
}
