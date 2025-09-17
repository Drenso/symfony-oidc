<?php

namespace Drenso\OidcBundle\Security\Factory;

use Drenso\OidcBundle\DependencyInjection\DrensoOidcExtension;
use Drenso\OidcBundle\Security\Exception\UnsupportedManagerException;
use Psr\Log\LoggerInterface;
use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\AbstractFactory;
use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\AuthenticatorFactoryInterface;
use Symfony\Component\DependencyInjection\ChildDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

class OidcTokenExchangeFactory extends AbstractFactory implements AuthenticatorFactoryInterface
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
  }

  public function getPriority(): int
  {
    return self::PRIORITY;
  }

  public function getKey(): string
  {
    return 'oidc_token_exchange';
  }

  public function createAuthenticator(
    ContainerBuilder $container,
    string $firewallName,
    array $config,
    string $userProviderId): string
  {
    $authenticatorId = sprintf('%s.%s', DrensoOidcExtension::TOKEN_EXCHANGE_AUTHENTICATOR_ID, $firewallName);
    $clientReference = new Reference(sprintf('%s.%s', DrensoOidcExtension::CLIENT_ID, $config['client']));

    $container
      ->setDefinition($authenticatorId, new ChildDefinition(DrensoOidcExtension::TOKEN_EXCHANGE_AUTHENTICATOR_ID))
      ->addArgument($clientReference)
      ->addArgument(new Reference($userProviderId))
      ->addArgument(new Reference(LoggerInterface::class))
      ->addArgument($config['user_identifier_property']);

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
