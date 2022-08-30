<?php

namespace Drenso\OidcBundle;

interface OidcWellKnownParserInterface
{
  public function parseWellKnown(array $config): array;
}
