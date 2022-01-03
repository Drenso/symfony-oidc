<?php

namespace Drenso\OidcBundle\DependencyInjection;

use Drenso\OidcBundle\OidcClientInterface;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ChildDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Loader;
use Symfony\Component\DependencyInjection\Reference;

class DrensoOidcExtension extends Extension
{
  const BASE_ID = 'drenso.oidc.';
  const AUTHENTICATOR_ID = self::BASE_ID . 'authenticator';
  const URL_FETCHER_ID = self::BASE_ID . 'url_fetcher';
  const JWT_HELPER_ID = self::BASE_ID . 'jwt_helper';
  const CLIENT_ID = self::BASE_ID . 'client';

  public function load(array $configs, ContainerBuilder $container): void
  {
    // Autoload configured services
    $loader = new Loader\PhpFileLoader($container, new FileLocator(__DIR__ . '/../Resources/config'));
    $loader->load('services.php');

    // Parse configuration
    $configuration = new Configuration();
    $config        = $this->processConfiguration($configuration, $configs);

    // Load the configured clients
    foreach ($config['clients'] as $clientName => $clientConfig) {
      $this->registerClient($container, $clientName, $clientConfig);
    }

    // Setup default alias
    $container
        ->setAlias(OidcClientInterface::class, sprintf('drenso.oidc.client.%s', $config['default_client']));
  }

  private function registerClient(ContainerBuilder $container, string $name, array $config): void
  {
    $urlFetcherId = sprintf('%s.%s', self::URL_FETCHER_ID, $name);
    $container
        ->setDefinition($urlFetcherId, new ChildDefinition(self::URL_FETCHER_ID))
        ->addArgument($config['custom_client_headers']);

    $jwtHelperId = sprintf('%s.%s', self::JWT_HELPER_ID, $name);
    $container
        ->setDefinition($jwtHelperId, new ChildDefinition(self::JWT_HELPER_ID))
        ->addArgument(new Reference($urlFetcherId))
        ->addArgument($config['client_id']);

    $clientId = sprintf('%s.%s', self::CLIENT_ID, $name);
    $container
        ->setDefinition($clientId, new ChildDefinition(self::CLIENT_ID))
        ->addArgument(new Reference($urlFetcherId))
        ->addArgument(new Reference($jwtHelperId))
        ->addArgument($config['well_known_url'])
        ->addArgument($config['well_known_cache_time'])
        ->addArgument($config['client_id'])
        ->addArgument($config['client_secret'])
        ->addArgument($config['redirect_route']);

    $container
        ->registerAliasForArgument($clientId, OidcClientInterface::class, sprintf('%sOidcClient', $name));
  }
}
