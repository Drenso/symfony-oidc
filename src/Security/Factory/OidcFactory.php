<?php

namespace Drenso\OidcBundle\Security\Factory;

use Drenso\OidcBundle\Security\EntryPoint\OidcEntryPoint;
use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\AbstractFactory;
use Symfony\Component\DependencyInjection\ChildDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

class OidcFactory extends AbstractFactory
{
  /**
   * Defines the configuration key used to reference the provider
   * in the firewall configuration.
   *
   * @return string
   */
  public function getKey()
  {
    return 'oidc';
  }

  /**
   * Defines the position at which the provider is called.
   * Possible values: pre_auth, form, http, and remember_me.
   *
   * @return string
   */
  public function getPosition()
  {
    return 'http';
  }

  /**
   * Subclasses must return the id of a service which implements the
   * AuthenticationProviderInterface.
   *
   * @param ContainerBuilder $container
   * @param string           $id             The unique id of the firewall
   * @param array            $config         The options array for this listener
   * @param string           $userProviderId The id of the user provider
   *
   * @return string never null, the id of the authentication provider
   *
   * @suppress PhanParamSignatureRealMismatchHasNoParamType
   */
  protected function createAuthProvider(ContainerBuilder $container, $id, $config, $userProviderId)
  {
    $providerId = sprintf("%s.%s", $this->getProviderKey(), $id);

    $container
        ->setDefinition($providerId, new ChildDefinition($this->getProviderKey()))
        ->replaceArgument(0, new Reference($userProviderId));

    return $providerId;
  }

  /**
   * Subclasses must return the id of the listener template.
   *
   * Listener definitions should inherit from the AbstractAuthenticationListener
   * like this:
   *
   *    <service id="my.listener.id"
   *             class="My\Concrete\Classname"
   *             parent="security.authentication.listener.abstract"
   *             abstract="true" />
   *
   * In the above case, this method would return "my.listener.id".
   *
   * @return string
   */
  protected function getListenerId()
  {
    return 'security.authentication.listener.oidc';
  }

  /**
   * @return string
   */
  protected function getProviderKey()
  {
    return 'security.authentication.provider.oidc';
  }

  /**
   * Creates an entry point for this authentication. Can be disabled by clearing the login_path route.
   *
   * @inheritDoc
   * @suppress PhanParamSignatureRealMismatchHasNoParamType
   */
  protected function createEntryPoint($container, $id, $config, $defaultEntryPointId)
  {
    if (!$defaultEntryPointId && !empty($config['login_path'])) {
      $entryPointId = 'security.authentication.entry_point.oidc.' . $id;
      $container
          ->setDefinition($entryPointId, new Definition(OidcEntryPoint::class))
          ->addArgument(new Reference('security.http_utils'))
          ->addArgument($config['login_path']);

      return $entryPointId;
    }

    // Fall back to default behavior
    return parent::createEntryPoint($container, $id, $config, $defaultEntryPointId);
  }
}
