<?php

namespace Drenso\OidcBundle;

use Drenso\OidcBundle\Exception\OidcClientNotFoundException;
use Psr\Container\ContainerInterface;
use Throwable;

class OidcClientLocator
{
  public function __construct(private readonly ContainerInterface $locator, private readonly string $defaultClient)
  {
  }

  /** @throws OidcClientNotFoundException */
  public function getClient(?string $name = null): OidcClientInterface
  {
    $name ??= $this->defaultClient;
    if (!$this->locator->has($name)) {
      throw new OidcClientNotFoundException($name);
    }

    try {
      return $this->locator->get($name);
    } catch (Throwable $e) {
      throw new OidcClientNotFoundException($name, $e);
    }
  }
}
