<?php

namespace Drenso\OidcBundle\Security\Factory;

use Drenso\OidcBundle\DependencyInjection\DrensoOidcExtension;
use Drenso\OidcBundle\EventListener\OidcEndSessionSubscriber;
use Drenso\OidcBundle\Security\Exception\UnsupportedManagerException;
use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\AbstractFactory;
use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\AuthenticatorFactoryInterface;
use Symfony\Component\DependencyInjection\ChildDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

class OidcFactory extends AbstractFactory implements AuthenticatorFactoryInterface
{
  public const PRIORITY = -5;

  public function __construct()
  {
    // Remove unused options
    unset($this->options['use_forward']);
    unset($this->options['require_previous_session']);

    // Set extra options
    $this->addOption('client', 'default');
    $this->addOption('user_identifier_property', 'sub');
    $this->addOption('user_identifier_from_idtoken', false);
    $this->addOption('enable_remember_me', false);
    $this->addOption('enable_end_session_listener', false);
    $this->addOption('use_logout_target_path', true);
  }

  public function getPriority(): int
  {
    return self::PRIORITY;
  }

  public function getKey(): string
  {
    return 'oidc';
  }

  public function createAuthenticator(
    ContainerBuilder $container,
    string $firewallName,
    array $config,
    string $userProviderId): string
  {
    $authenticatorId = sprintf('%s.%s', DrensoOidcExtension::AUTHENTICATOR_ID, $firewallName);
    $clientReference = new Reference(sprintf('%s.%s', DrensoOidcExtension::CLIENT_ID, $config['client']));

    $container
      ->setDefinition($authenticatorId, new ChildDefinition(DrensoOidcExtension::AUTHENTICATOR_ID))
      ->addArgument(new Reference('security.http_utils'))
      ->addArgument($clientReference)
      ->addArgument(new Reference(sprintf('%s.%s', DrensoOidcExtension::SESSION_STORAGE_ID, $config['client'])))
      ->addArgument(new Reference($userProviderId))
      ->addArgument(new Reference($this->createAuthenticationSuccessHandler($container, $firewallName, $config)))
      ->addArgument(new Reference($this->createAuthenticationFailureHandler($container, $firewallName, $config)))
      ->addArgument($config['check_path'])
      ->addArgument($config['login_path'])
      ->addArgument($config['user_identifier_property'])
      ->addArgument($config['enable_remember_me'])
      ->addArgument($config['user_identifier_from_idtoken']);

    $logoutListenerId = sprintf('security.logout.listener.default.%s', $firewallName);

    // Check if "logout" config is specified in the firewall and "enable_end_session_listener" is set to true
    if ($config['enable_end_session_listener'] && $container->hasDefinition($logoutListenerId)) {
      $endSessionListenerId = sprintf('%s.%s', DrensoOidcExtension::END_SESSION_LISTENER_ID, $firewallName);

      /** If "use_logout_target_path" is true (default) pass the target path to the {@see OidcEndSessionSubscriber} */
      $logoutTargetPath = $config['use_logout_target_path']
          ? $container->getDefinition($logoutListenerId)->getArgument(1)
          : null;

      $container
        ->setDefinition($endSessionListenerId, new Definition(OidcEndSessionSubscriber::class))
        ->addArgument($clientReference)
        ->addArgument(new Reference('security.http_utils'))
        ->addArgument($logoutTargetPath) // Set the configured logout target path (null or string)
        ->addTag('kernel.event_subscriber', [
          'dispatcher' => sprintf('security.event_dispatcher.%s', $firewallName),
        ])
      ;
    }

    return $authenticatorId;
  }

  /**
   * The following methods are required for Symfony 5.4 compatibility, but are not used.
   *
   * @todo: Remove when dropping support for Symfony 5.4
   */
  protected function createAuthProvider(
    ContainerBuilder $container,
    string $id,
    array $config,
    string $userProviderId): string
  {
    throw new UnsupportedManagerException();
  }

  protected function getListenerId(): string
  {
    throw new UnsupportedManagerException();
  }

  public function getPosition(): string
  {
    throw new UnsupportedManagerException();
  }
}
