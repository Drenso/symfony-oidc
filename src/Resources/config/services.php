<?php

use Drenso\OidcBundle\DependencyInjection\DrensoOidcExtension;
use Drenso\OidcBundle\OidcClient;
use Drenso\OidcBundle\OidcJwtHelper;
use Drenso\OidcBundle\OidcUrlFetcher;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Routing\RouterInterface;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

return function (ContainerConfigurator $configurator) {
  $configurator->services()
      ->set(DrensoOidcExtension::URL_FETCHER_ID, OidcUrlFetcher::class)
        ->abstract()

      ->set(DrensoOidcExtension::JWT_HELPER_ID, OidcJwtHelper::class)
        ->args([
            service(RequestStack::class),
        ])
        ->abstract()

      ->set(DrensoOidcExtension::CLIENT_ID, OidcClient::class)
        ->args([
            service(RequestStack::class),
            service(RouterInterface::class),
        ])
        ->abstract();
};
