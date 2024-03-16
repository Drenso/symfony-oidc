<?php

namespace Drenso\OidcBundle\Security;

use Drenso\OidcBundle\Exception\OidcException;
use Drenso\OidcBundle\OidcClientInterface;
use Drenso\OidcBundle\OidcJwtHelper;
use Drenso\OidcBundle\OidcSessionStorage;
use Drenso\OidcBundle\Security\Exception\OidcAuthenticationException;
use Drenso\OidcBundle\Security\Exception\UnsupportedManagerException;
use Drenso\OidcBundle\Security\Token\OidcToken;
use Drenso\OidcBundle\Security\UserProvider\OidcUserProviderInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\Authenticator\InteractiveAuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\RememberMeBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\PassportInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Component\Security\Http\HttpUtils;

class OidcAuthenticator implements InteractiveAuthenticatorInterface, AuthenticationEntryPointInterface
{
  public function __construct(
    private readonly HttpUtils $httpUtils,
    private readonly OidcClientInterface $oidcClient,
    private readonly OidcSessionStorage $sessionStorage,
    private readonly OidcUserProviderInterface $oidcUserProvider,
    private readonly AuthenticationSuccessHandlerInterface $successHandler,
    private readonly AuthenticationFailureHandlerInterface $failureHandler,
    private readonly string $checkPath,
    private readonly string $loginPath,
    private readonly string $userIdentifierProperty,
    private readonly bool $enableRememberMe,
    private readonly bool $userIdentifierFromIdToken = false
  ) {
  }

  public function supports(Request $request): ?bool
  {
    return
        $this->httpUtils->checkRequestPath($request, $this->checkPath)
        && $request->query->has('code')
        && $request->query->has('state');
  }

  public function start(Request $request, ?AuthenticationException $authException = null): Response
  {
    return $this->httpUtils->createRedirectResponse($request, $this->loginPath);
  }

  public function authenticate(Request $request): Passport
  {
    try {
      // Try to authenticate the request
      $authData = $this->oidcClient->authenticate($request);

      // Retrieve the user data with the authentication data
      $userData = $this->oidcClient->retrieveUserInfo($authData);

      // Look for the user identifier in either the id_token or the userinfo endpoint
      if ($this->userIdentifierFromIdToken) {
        $userIdentifier = OidcJwtHelper::parseToken($authData->getIdToken())
          ->claims()
          ->get($this->userIdentifierProperty);
      } else {
        $userIdentifier = $userData->getUserDataString($this->userIdentifierProperty);
      }

      // Ensure the user exists
      if (!$userIdentifier) {
        throw new UserNotFoundException(
          sprintf('User identifier property (%s) yielded empty user identifier', $this->userIdentifierProperty));
      }
      $this->oidcUserProvider->ensureUserExists($userIdentifier, $userData);

      // Create the passport
      $passport = new SelfValidatingPassport(new UserBadge(
        $userIdentifier,
        fn (string $userIdentifier) => $this->oidcUserProvider->loadOidcUser($userIdentifier),
      ));
      $passport->setAttribute(OidcToken::AUTH_DATA_ATTR, $authData);
      $passport->setAttribute(OidcToken::USER_DATA_ATTR, $userData);

      if ($this->enableRememberMe && $this->sessionStorage->getRememberMe()) {
        // Add remember me badge when enabled
        $passport->addBadge((new RememberMeBadge())->enable());
        $this->sessionStorage->clearRememberMe();
      }

      return $passport;
    } catch (OidcException $e) {
      throw new OidcAuthenticationException('OIDC authentication failed', $e);
    }
  }

  public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
  {
    return $this->successHandler->onAuthenticationSuccess($request, $token);
  }

  public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
  {
    return $this->failureHandler->onAuthenticationFailure($request, $exception);
  }

  public function createToken(Passport $passport, string $firewallName): TokenInterface
  {
    return new OidcToken($passport, $firewallName);
  }

  /**
   * @todo: Remove when dropping support for Symfony 5.4
   *
   * @phan-suppress PhanUndeclaredTypeParameter
   */
  public function createAuthenticatedToken(
    PassportInterface $passport,
    string $firewallName): TokenInterface
  {
    throw new UnsupportedManagerException();
  }

  public function isInteractive(): bool
  {
    return true;
  }
}
