<?php

namespace Drenso\OidcBundle;

use Drenso\OidcBundle\Security\Factory\OidcFactory;
use Symfony\Bundle\SecurityBundle\DependencyInjection\SecurityExtension;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;

class DrensoOidcBundle extends Bundle
{
  public function build(ContainerBuilder $container): void
  {
    parent::build($container);

    // Register our OIDC factory
    $extension = $container->getExtension('security');
    assert($extension instanceof SecurityExtension);
    $extension->addAuthenticatorFactory(new OidcFactory());
  }
}
