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
        ->fixXmlConfig('client')
        ->children()
          ->scalarNode('default_client')
            ->info('The default client to use')
            ->defaultValue('default')
          ->end()
          ->arrayNode('clients')
            ->useAttributeAsKey('name')
            ->requiresAtLeastOneElement()
            ->arrayPrototype()
              ->children()
                ->scalarNode('well_known_url')
                  ->isRequired()
                ->end() // well_known_url
                ->scalarNode('client_id')
                  ->isRequired()
                ->end() // client_id
                ->scalarNode('client_secret')
                  ->isRequired()
                ->end() // client_secret
                ->scalarNode('redirect_route')
                  ->defaultValue('login_check')
                ->end() // redirect_route
                ->arrayNode('custom_client_headers')
                  ->scalarPrototype()->end()
                ->end() // custom_client_headers
              ->end() // array prototype children
            ->end() // array prototype
          ->end() // clients
        ->end(); // root children

    return $treeBuilder;
  }
}
