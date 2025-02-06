<?php

namespace Drenso\OidcBundle;

interface OidcWellKnownParserInterface
{
  /**
   * @param array<string, mixed> $config
   *
   * @return array<string, mixed>
   */
  public function parseWellKnown(array $config): array;
}
