<?php

namespace Drenso\OidcBundle\DependencyInjection;

use Drenso\OidcBundle\Http\OAuth2TokenExchangeFactory;
use Drenso\OidcBundle\Http\OAuth2TokenExchangeFactoryInterface;
use Drenso\OidcBundle\OidcClientInterface;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ChildDefinition;
use Symfony\Component\DependencyInjection\Compiler\ServiceLocatorTagPass;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\HttpKernel\DependencyInjection\ConfigurableExtension;

class DrensoOidcExtension extends ConfigurableExtension
{
  public const BASE_ID                   = 'drenso.oidc.';
  public const AUTHENTICATOR_ID          = self::BASE_ID . 'authenticator';
  public const URL_FETCHER_ID            = self::BASE_ID . 'url_fetcher';
  public const JWT_HELPER_ID             = self::BASE_ID . 'jwt_helper';
  public const SESSION_STORAGE_ID        = self::BASE_ID . 'session_storage';
  public const CLIENT_ID                 = self::BASE_ID . 'client';
  public const CLIENT_LOCATOR_ID         = self::BASE_ID . 'client_locator';
  public const END_SESSION_LISTENER_ID   = self::BASE_ID . 'end_session_listener';
  public const TOKEN_EXCHANGE_FACTORY_ID = self::BASE_ID . 'token_exchange_factory';

  /** @param array<string, mixed> $mergedConfig */
  public function loadInternal(array $mergedConfig, ContainerBuilder $container): void
  {
    // Autoload configured services
    $loader = new PhpFileLoader($container, new FileLocator(__DIR__ . '/../Resources/config'));
    $loader->load('services.php');

    // Load the configured clients
    $clientServices               = [];
    $tokenExchangeFactoryServices = [];
    foreach ($mergedConfig['clients'] as $clientName => $clientConfig) {
      $clientServices[$clientName] = $this->registerClient($container, $clientName, $clientConfig);

      // Register token exchange factories for this client
      if (isset($clientConfig['token_exchange_factories'])) {
        foreach ($clientConfig['token_exchange_factories'] as $factoryName => $factoryConfig) {
          $tokenExchangeFactoryServices[$factoryName] = $this->registerTokenExchangeFactory($container, $clientName, $factoryName, $factoryConfig, $mergedConfig, $clientServices[$clientName]);
        }
      }
    }

    // Setup default alias
    $container
      ->setAlias(OidcClientInterface::class, sprintf('drenso.oidc.client.%s', $mergedConfig['default_client']));

    // Setup default token exchange factory alias if any factories exist for the default client
    $defaultClientName = $mergedConfig['default_client'];
    if (isset($mergedConfig['clients'][$defaultClientName]['token_exchange_factories'])) {
      $defaultClientFactories = $mergedConfig['clients'][$defaultClientName]['token_exchange_factories'];
      if (!empty($defaultClientFactories)) {
        $firstDefaultFactory = array_key_first($defaultClientFactories);
        $defaultFactoryId    = sprintf('%s.%s.%s', self::TOKEN_EXCHANGE_FACTORY_ID, $defaultClientName, $firstDefaultFactory);
        $container
          ->setAlias(OAuth2TokenExchangeFactoryInterface::class, $defaultFactoryId);
      }
    }

    // Configure client locator
    $container
      ->getDefinition(self::CLIENT_LOCATOR_ID)
      ->addArgument(ServiceLocatorTagPass::register($container, $clientServices))
      ->addArgument($mergedConfig['default_client']);
  }

  /** @param array<string, mixed> $config */
  private function registerClient(ContainerBuilder $container, string $name, array $config): Reference
  {
    $urlFetcherId = sprintf('%s.%s', self::URL_FETCHER_ID, $name);
    $container
      ->setDefinition($urlFetcherId, new ChildDefinition(self::URL_FETCHER_ID))
      ->addArgument($config['custom_client_headers'])
      ->addArgument($config['custom_client_options']);

    $sessionStorageId = sprintf('%s.%s', self::SESSION_STORAGE_ID, $name);
    $container
      ->setDefinition($sessionStorageId, new ChildDefinition(self::SESSION_STORAGE_ID))
      ->addArgument($name);

    $jwtHelperId                          = sprintf('%s.%s', self::JWT_HELPER_ID, $name);
    $additionalTokenConstraintsProviderId = $config['additional_token_constraints_provider'];
    $container
      ->setDefinition($jwtHelperId, new ChildDefinition(self::JWT_HELPER_ID))
      ->addArgument(new Reference($urlFetcherId))
      ->addArgument(new Reference($sessionStorageId))
      ->addArgument($config['client_id'])
      ->addArgument($config['jwks_cache_time'])
      ->addArgument($config['token_leeway_seconds'])
      ->addArgument($additionalTokenConstraintsProviderId ? new Reference($additionalTokenConstraintsProviderId) : null);

    $clientId          = sprintf('%s.%s', self::CLIENT_ID, $name);
    $wellKnownParserId = $config['well_known_parser'];
    $container
      ->setDefinition($clientId, new ChildDefinition(self::CLIENT_ID))
      ->addArgument(new Reference($urlFetcherId))
      ->addArgument(new Reference($sessionStorageId))
      ->addArgument(new Reference($jwtHelperId))
      ->addArgument($config['well_known_url'])
      ->addArgument($config['well_known_cache_time'])
      ->addArgument($config['client_id'])
      ->addArgument($config['client_secret'])
      ->addArgument($config['redirect_route'])
      ->addArgument($config['remember_me_parameter'])
      ->addArgument($wellKnownParserId ? new Reference($wellKnownParserId) : null)
      ->addArgument($config['code_challenge_method'])
      ->addArgument($config['disable_nonce']);

    $container
      ->registerAliasForArgument($clientId, OidcClientInterface::class, sprintf('%sOidcClient', $name));

    return new Reference($clientId);
  }

  /**
   * @param array<string, mixed> $config
   * @param array<string, mixed> $mergedConfig
   */
  private function registerTokenExchangeFactory(ContainerBuilder $container, string $clientName, string $factoryName, array $config, array $mergedConfig, Reference $client): Reference
  {
    $factoryId        = sprintf('%s.%s.%s', self::TOKEN_EXCHANGE_FACTORY_ID, $clientName, $factoryName);
    $sessionStorageId = sprintf('%s.%s', self::SESSION_STORAGE_ID, $clientName);
    $clientId         = sprintf('%s.%s', self::CLIENT_ID, $clientName);

    $container
      ->setDefinition($factoryId, new Definition(OAuth2TokenExchangeFactory::class))
      ->addArgument(new Reference($sessionStorageId))
      ->addArgument($client)
      ->addArgument($config['scope'])
      ->addArgument($config['audience'])
      ->addArgument(new Reference('logger'))
      ->addArgument(new Reference('cache.app'))
      ->addArgument($config['cache_time']);

    // Use client prefix only for non-default clients
    $defaultClientName = $mergedConfig['default_client'] ?? 'default';
    $autowiringName    = ($clientName === $defaultClientName)
      ? sprintf('%sTokenExchangeFactory', ucfirst($factoryName))
      : sprintf('%s%sTokenExchangeFactory', $clientName, ucfirst($factoryName));

    $container
      ->registerAliasForArgument($factoryId, OAuth2TokenExchangeFactoryInterface::class, $autowiringName);

    return new Reference($factoryId);
  }
}
