<?php

namespace Drenso\OidcBundle\EventListener;

use Drenso\OidcBundle\Exception\OidcConfigurationException;
use Drenso\OidcBundle\Exception\OidcConfigurationResolveException;
use Drenso\OidcBundle\Exception\OidcException;
use Drenso\OidcBundle\OidcClientInterface;
use Drenso\OidcBundle\Security\Token\OidcToken;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\Security\Http\Event\LogoutEvent;
use Symfony\Component\Security\Http\HttpUtils;

class OidcEndSessionSubscriber implements EventSubscriberInterface
{
  public function __construct(
      private OidcClientInterface $oidcClient,
      private HttpUtils $httpUtils,
      private ?string $logoutTarget = null)
  {
  }

  /**
   * @throws OidcConfigurationException
   * @throws OidcConfigurationResolveException
   * @throws OidcException
   */
  public function onLogout(LogoutEvent $event): void
  {
    $token = $event->getToken();

    if (!$token instanceof OidcToken) {
      return;
    }

    $postLogoutRedirectUrl = null !== $this->logoutTarget
        ? $this->httpUtils->generateUri($event->getRequest(), $this->logoutTarget)
        : null;

    $event->setResponse($this->oidcClient->generateEndSessionEndpointRedirect(
        $token->getAuthData(),
        $postLogoutRedirectUrl
    ));
  }

  public static function getSubscribedEvents(): array
  {
    return [LogoutEvent::class => 'onLogout'];
  }
}
