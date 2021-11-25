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
          ->end()
          ->scalarNode('client_id')
            ->isRequired()
          ->end()
          ->scalarNode('client_secret')
            ->isRequired()
          ->end()
          ->scalarNode('redirect_route')
            ->defaultValue('login_check')
          ->end()
          ->arrayNode('custom_client_headers')
            ->scalarPrototype()->end()
          ->end()
        ->end();

    return $treeBuilder;
  }
}
