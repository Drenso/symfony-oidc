<?php

namespace Drenso\OidcBundle\Security\Firewall;

use Drenso\OidcBundle\Exception\OidcException;
use Drenso\OidcBundle\OidcClient;
use Drenso\OidcBundle\Security\Authentication\Token\OidcToken;
use Drenso\OidcBundle\Security\Exception\OidcAuthenticationException;
use InvalidArgumentException;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\Firewall\AbstractAuthenticationListener;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface;

class OidcListener extends AbstractAuthenticationListener
{

  /**
   * @var OidcClient
   */
  protected $OidcClient;

  /**
   * OidcListener constructor.
   *
   * @param TokenStorageInterface                  $tokenStorage
   * @param AuthenticationManagerInterface         $authenticationManager
   * @param SessionAuthenticationStrategyInterface $sessionStrategy
   * @param HttpUtils                              $httpUtils
   * @param string                                 $providerKey
   * @param AuthenticationSuccessHandlerInterface  $successHandler
   * @param AuthenticationFailureHandlerInterface  $failureHandler
   * @param array                                  $options
   * @param LoggerInterface|NULL                   $logger
   * @param OidcClient|NULL                        $oidcClient
   */
  public function __construct(
      TokenStorageInterface $tokenStorage, AuthenticationManagerInterface $authenticationManager,
      SessionAuthenticationStrategyInterface $sessionStrategy, HttpUtils $httpUtils, string $providerKey,
      AuthenticationSuccessHandlerInterface $successHandler, AuthenticationFailureHandlerInterface $failureHandler,
      array $options = array(), LoggerInterface $logger = NULL, OidcClient $oidcClient = NULL)
  {
    parent::__construct($tokenStorage, $authenticationManager, $sessionStrategy, $httpUtils,
        $providerKey, $successHandler, $failureHandler, $options, $logger);

    if (!$oidcClient) {
      throw new InvalidArgumentException("OIDC client must be set!");
    }

    $this->OidcClient = $oidcClient;
  }

  /**
   * Performs authentication.
   *
   * @param Request $request
   *
   * @return TokenInterface|Response|null The authenticated token, null if full authentication
   *                                      is not possible, or a Response
   *
   * @throws AuthenticationException if the authentication fails
   */
  protected function attemptAuthentication(Request $request)
  {
    /**
     * Try to validate the request. If we cannot validate it here, there was no forward
     * from the OIDC provider containing the required information for this listener.
     */
    try {
      // Try to authenticate the request
      if (($authData = $this->OidcClient->authenticate($request)) === NULL) {
        return NULL;
      }

      // Retrieve the user date with the authentication data
      $userData = $this->OidcClient->retrieveUserInfo($authData);

      // Create token
      $token = new OidcToken();
      $token
        ->setUserData($userData)
        ->setAuthData($authData);

      // Try to authenticate this against the Symfony authentication backend
      return $this->authenticationManager->authenticate($token);

    } catch (OidcException $e) {
      throw new OidcAuthenticationException("Request validation failed", NULL, $e);
    }

  }
}
