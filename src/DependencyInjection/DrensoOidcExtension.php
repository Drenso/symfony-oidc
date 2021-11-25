<?php

namespace Drenso\OidcBundle\DependencyInjection;

use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Loader;

class DrensoOidcExtension extends Extension
{
  public function load(array $configs, ContainerBuilder $container)
  {
    // Autoload configured services
    $loader = new Loader\PhpFileLoader($container, new FileLocator(__DIR__ . '/../Resources/config'));
    $loader->load('services.php');

    // Parse configuration
    $configuration = new Configuration();
    $config        = $this->processConfiguration($configuration, $configs);

    // Load configuration values into parameters
    $container->setParameter('drenso.oidc.well_known_url', $config['well_known_url']);
    $container->setParameter('drenso.oidc.client_id', $config['client_id']);
    $container->setParameter('drenso.oidc.client_secret', $config['client_secret']);
    $container->setParameter('drenso.oidc.redirect_route', $config['redirect_route']);
    $container->setParameter('drenso.oidc.custom_client_headers', $config['custom_client_headers']);
  }
}
