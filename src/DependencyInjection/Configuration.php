<?php

namespace Drenso\OidcBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

class Configuration implements ConfigurationInterface
{
  public function getConfigTreeBuilder()
  {
    $treeBuilder = new TreeBuilder('drenso_oidc');

    $treeBuilder->getRootNode()
        ->children()
          ->scalarNode('well_known_url')
            ->isRequired()
            ->cannotBeEmpty()
            ->validate()
              ->ifTrue(fn($v) => filter_var($v, FILTER_VALIDATE_URL) === false)
              ->thenInvalid('Invalid well known url %s')
            ->end()
          ->end()
          ->scalarNode('client_id')
            ->isRequired()
            ->cannotBeEmpty()
          ->end()
          ->scalarNode('client_secret')
            ->isRequired()
            ->cannotBeEmpty()
          ->end()
          ->scalarNode('redirect_route')
            ->defaultValue('login_check')
            ->cannotBeEmpty()
          ->end()
          ->arrayNode('custom_client_headers')
            ->scalarPrototype()->end()
          ->end()
        ->end();

    return $treeBuilder;
  }
}
