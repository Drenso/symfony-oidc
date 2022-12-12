<?php

namespace Drenso\OidcBundle\EventListener;

use Drenso\OidcBundle\Exception\OidcConfigurationException;
use Drenso\OidcBundle\Exception\OidcConfigurationResolveException;
use Drenso\OidcBundle\Exception\OidcException;
use Drenso\OidcBundle\Model\OidcTokens;
use Drenso\OidcBundle\OidcClientInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\TokenNotFoundException;
use Symfony\Component\Security\Http\Event\LogoutEvent;
use Symfony\Component\Security\Http\HttpUtils;

class OidcEndSessionSubscriber implements EventSubscriberInterface
{
  public function __construct(
     private OidcClientInterface $oidcClient,
     private HttpUtils $httpUtils,
     private string $logoutTarget
  ) {
  }

  /**
   * @throws OidcConfigurationException
   * @throws OidcConfigurationResolveException
   * @throws OidcException
   */
  public function onLogout(LogoutEvent $event): void
  {
    $token = $event->getToken();

    if (!$token instanceof TokenInterface) {
      throw new TokenNotFoundException();
    }

    $oidcTokens = $token->getAttribute('auth_data');

    if (!$oidcTokens instanceof OidcTokens) {
      throw new OidcException('Invalid token object.');
    }

    $postLogoutRedirectUrl = $this->httpUtils->generateUri($event->getRequest(), $this->logoutTarget);

    $event->setResponse($this->oidcClient->generateEndSessionEndpointRedirect($oidcTokens, $postLogoutRedirectUrl));
  }

  public static function getSubscribedEvents(): array
  {
    return [LogoutEvent::class => 'onLogout'];
  }
}
