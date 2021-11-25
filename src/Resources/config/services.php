<?php

use Drenso\OidcBundle\OidcClient;
use Drenso\OidcBundle\OidcJwtHelper;
use Drenso\OidcBundle\OidcUrlFetcher;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\param;

return function (ContainerConfigurator $configurator) {
  $services = $configurator
      ->services()
      ->defaults()
      ->private()
      ->autowire()
      ->autoconfigure();

  $services
      ->load('Drenso\\OidcBundle\\', '../../*')
      ->exclude('../../{DependencyInjection,Model,Security}');

  $services
      ->get(OidcClient::class)
      ->arg(4, param('drenso.oidc.well_known_url'))
      ->arg(5, param('drenso.oidc.client_id'))
      ->arg(6, param('drenso.oidc.client_secret'))
      ->arg(7, param('drenso.oidc.redirect_route'));

  $services
      ->get(OidcJwtHelper::class)
      ->arg(2, param('drenso.oidc.client_id'));

  $services
      ->get(OidcUrlFetcher::class)
      ->arg(0, param('drenso.oidc.custom_client_headers'));
};
